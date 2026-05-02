/*
 * Parallel signature verification for lunarblock
 *
 * Uses a pthread worker pool to verify multiple transaction inputs in parallel.
 * Each worker has its own secp256k1 context for thread-safe verification.
 *
 * Workers consume from a single unified queue. Jobs are tagged with a type
 * discriminator (PV_JOB_INPUT or PV_JOB_SIG) so the same worker pool can
 * service both pv_verify_batch (legacy input-verify framework) and
 * pv_verify_signatures (the production hot path that posts pre-computed
 * sighashes).
 *
 * Pre-2026-05-02 the pool was split into two queues: a `next_job` /
 * `job_count` queue that workers polled, and a separate `sig_next_job` /
 * `sig_job_count` queue that pv_verify_signatures populated. The latter was
 * never drained because `sig_worker_func` was never bound to pthread_create —
 * pv_verify_signatures broadcast on `work_available`, workers woke, saw the
 * INPUT queue empty, and went back to sleep. The main thread then waited
 * forever on `work_done`. Lunarblock hung at h=944,184 the first time the
 * sig path was exercised in production. Closure: unify the queue.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

/*
 * secp256k1 declarations (avoiding header dependency)
 * These match the libsecp256k1 ABI used by lunarblock.
 */
typedef struct secp256k1_context_struct secp256k1_context;
typedef struct { unsigned char data[64]; } secp256k1_pubkey;
typedef struct { unsigned char data[64]; } secp256k1_ecdsa_signature;

#define SECP256K1_CONTEXT_VERIFY 0x0101

secp256k1_context* secp256k1_context_create(unsigned int flags);
void secp256k1_context_destroy(secp256k1_context* ctx);

int secp256k1_ec_pubkey_parse(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    const unsigned char* input,
    size_t inputlen
);

int secp256k1_ecdsa_signature_parse_der(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char* input,
    size_t inputlen
);

int secp256k1_ecdsa_verify(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature* sig,
    const unsigned char* msghash32,
    const secp256k1_pubkey* pubkey
);

/* Job structure passed to workers (input-verification framework) */
typedef struct {
    const uint8_t *tx_data;       /* Serialized transaction */
    size_t tx_len;                /* Transaction length */
    uint32_t input_index;         /* Input index being verified */
    const uint8_t *prev_script;   /* Previous output scriptPubKey */
    size_t prev_script_len;       /* Length of prev_script */
    int64_t amount;               /* Satoshi value of the input */
    uint32_t flags;               /* Script verification flags */
    int result;                   /* 1 = valid, 0 = invalid, -1 = error */
} verify_job;

/* Pre-computed sighash signature-verification job. Lua computes the sighash
 * (which requires full tx parsing and script handling) and posts these for
 * parallel ECDSA verification. */
typedef struct {
    const uint8_t *pubkey;        /* Public key bytes (33 or 65) */
    size_t pubkey_len;            /* Public key length */
    const uint8_t *sig_der;       /* DER-encoded signature */
    size_t sig_len;               /* Signature length */
    const uint8_t *msghash32;     /* 32-byte message hash (sighash) */
    int result;                   /* 1 = valid, 0 = invalid */
} sig_verify_job;

/* Worker thread state */
typedef struct {
    pthread_t thread;
    secp256k1_context *ctx;
    int id;
    int running;
} worker_t;

/* Unified job-queue entry.
 *
 * The pool is single-batch at a time: pv_verify_batch and
 * pv_verify_signatures both grab queue_mutex, populate the queue, and wait
 * for completion before another batch can start. The discriminator lets a
 * single worker function dispatch to either kind.
 */
typedef enum {
    PV_JOB_INPUT = 1,   /* verify_job *      (placeholder framework) */
    PV_JOB_SIG   = 2    /* sig_verify_job *  (production hot path)   */
} pv_job_kind;

/* Global state */
static worker_t *workers = NULL;
static int num_workers = 0;
static int initialized = 0;

/* Unified job queue — used for both INPUT and SIG batches */
static pv_job_kind current_kind = PV_JOB_INPUT;
static void *job_queue = NULL;       /* verify_job[] or sig_verify_job[] */
static int job_count = 0;
static int jobs_completed = 0;
static int next_job = 0;

/* Synchronization */
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t work_available = PTHREAD_COND_INITIALIZER;
static pthread_cond_t work_done = PTHREAD_COND_INITIALIZER;
static int shutdown_flag = 0;

/* Minimum inputs to use parallel verification (overhead not worth it below this) */
#define MIN_PARALLEL_INPUTS 16

/*
 * Parse a DER-encoded signature into secp256k1_ecdsa_signature.
 * Returns 1 on success, 0 on failure.
 */
static int parse_der_signature(secp256k1_context *ctx,
                               secp256k1_ecdsa_signature *sig,
                               const uint8_t *der, size_t derlen) {
    return secp256k1_ecdsa_signature_parse_der(ctx, sig, der, derlen);
}

/*
 * Parse a public key into secp256k1_pubkey.
 * Supports both compressed (33 bytes) and uncompressed (65 bytes) formats.
 * Returns 1 on success, 0 on failure.
 */
static int parse_pubkey(secp256k1_context *ctx,
                        secp256k1_pubkey *pubkey,
                        const uint8_t *input, size_t inputlen) {
    return secp256k1_ec_pubkey_parse(ctx, pubkey, input, inputlen);
}

/*
 * Verify a single ECDSA signature.
 *
 * In production, the Lua side computes the sighash (which requires full
 * tx context) and passes the 32-byte hash for verification. This C code
 * focuses on the parallelization infrastructure.
 */
static int verify_ecdsa(secp256k1_context *ctx,
                        const uint8_t *pubkey_bytes, size_t pubkey_len,
                        const uint8_t *sig_der, size_t sig_len,
                        const uint8_t *msghash32) {
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;

    if (!parse_pubkey(ctx, &pubkey, pubkey_bytes, pubkey_len)) {
        return 0;
    }

    if (!parse_der_signature(ctx, &sig, sig_der, sig_len)) {
        return 0;
    }

    return secp256k1_ecdsa_verify(ctx, &sig, msghash32, &pubkey);
}

/*
 * Process one input-verify job (placeholder framework — Lua side does not
 * exercise this path in production, but kept so pv_verify_batch still
 * works for any caller that wants the input-verify scaffolding).
 */
static void process_input_job(worker_t *worker, verify_job *job) {
    (void)worker;
    /*
     * The actual verification is a placeholder that marks success. A full
     * implementation would:
     * 1. Deserialize the transaction from tx_data
     * 2. Get the input at input_index
     * 3. Compute the sighash based on script type and flags
     * 4. Extract signature and pubkey from scriptSig/witness
     * 5. Verify the signature
     *
     * The production path is process_sig_job below — Lua computes the
     * sighash and posts pre-computed sig_verify_job entries.
     */
    job->result = 1;  /* Placeholder: assume valid */
}

/*
 * Process one pre-computed sighash sig-verify job.
 * Runs ECDSA verify against the worker's per-thread secp256k1 context.
 */
static void process_sig_job(worker_t *worker, sig_verify_job *job) {
    job->result = verify_ecdsa(
        worker->ctx,
        job->pubkey, job->pubkey_len,
        job->sig_der, job->sig_len,
        job->msghash32
    );
}

/*
 * Unified worker thread function.
 *
 * Waits on the unified queue, dispatches per current_kind, signals
 * completion. There is no per-job-kind worker function because the same
 * threads must service both kinds of batches — a split queue caused the
 * h=944,184 deadlock when sig batches went unposted.
 */
static void *worker_func(void *arg) {
    worker_t *worker = (worker_t *)arg;

    while (1) {
        void *job_ptr = NULL;
        pv_job_kind kind = PV_JOB_INPUT;

        pthread_mutex_lock(&queue_mutex);

        while (next_job >= job_count && !shutdown_flag) {
            pthread_cond_wait(&work_available, &queue_mutex);
        }

        if (shutdown_flag) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }

        if (next_job < job_count) {
            int job_idx = next_job++;
            kind = current_kind;
            if (kind == PV_JOB_INPUT) {
                job_ptr = &((verify_job *)job_queue)[job_idx];
            } else {
                job_ptr = &((sig_verify_job *)job_queue)[job_idx];
            }
        }

        pthread_mutex_unlock(&queue_mutex);

        if (job_ptr != NULL) {
            if (kind == PV_JOB_INPUT) {
                process_input_job(worker, (verify_job *)job_ptr);
            } else {
                process_sig_job(worker, (sig_verify_job *)job_ptr);
            }

            pthread_mutex_lock(&queue_mutex);
            jobs_completed++;
            if (jobs_completed == job_count) {
                pthread_cond_signal(&work_done);
            }
            pthread_mutex_unlock(&queue_mutex);
        }
    }

    return NULL;
}

/*
 * Initialize the worker pool.
 *
 * @param num_threads Number of worker threads (0 = auto-detect based on CPU cores)
 * @return Number of workers created, or -1 on error
 */
int pv_init(int num_threads) {
    if (initialized) {
        return num_workers;
    }

    /* Auto-detect number of threads */
    if (num_threads <= 0) {
        long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpus < 1) ncpus = 1;
        /* Use ncpus - 1, but at least 1 */
        num_threads = (int)(ncpus > 1 ? ncpus - 1 : 1);
    }

    /* Cap at reasonable maximum */
    if (num_threads > 64) {
        num_threads = 64;
    }

    workers = (worker_t *)calloc(num_threads, sizeof(worker_t));
    if (!workers) {
        return -1;
    }

    num_workers = num_threads;
    shutdown_flag = 0;

    /* Create worker threads */
    for (int i = 0; i < num_workers; i++) {
        workers[i].id = i;
        workers[i].running = 0;

        /* Create per-thread secp256k1 context for verification */
        workers[i].ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        if (!workers[i].ctx) {
            /* Cleanup on failure */
            for (int j = 0; j < i; j++) {
                if (workers[j].ctx) {
                    secp256k1_context_destroy(workers[j].ctx);
                }
            }
            free(workers);
            workers = NULL;
            num_workers = 0;
            return -1;
        }

        if (pthread_create(&workers[i].thread, NULL, worker_func, &workers[i]) != 0) {
            /* Cleanup on failure */
            secp256k1_context_destroy(workers[i].ctx);
            for (int j = 0; j < i; j++) {
                shutdown_flag = 1;
                pthread_cond_broadcast(&work_available);
                pthread_join(workers[j].thread, NULL);
                secp256k1_context_destroy(workers[j].ctx);
            }
            free(workers);
            workers = NULL;
            num_workers = 0;
            return -1;
        }

        workers[i].running = 1;
    }

    initialized = 1;
    return num_workers;
}

/*
 * Verify a batch of inputs in parallel.
 *
 * @param jobs Array of verify_job structures
 * @param count Number of jobs in the array
 * @return Number of failures (0 = all passed), or -1 on error
 */
int pv_verify_batch(verify_job *jobs, int count) {
    if (!initialized) {
        /* Auto-initialize if needed */
        if (pv_init(0) < 0) {
            return -1;
        }
    }

    if (count <= 0) {
        return 0;
    }

    /* For small batches, skip parallel overhead */
    if (count < MIN_PARALLEL_INPUTS || num_workers <= 1) {
        /* Single-threaded verification */
        int failures = 0;

        for (int i = 0; i < count; i++) {
            /* Placeholder: mark all as valid */
            jobs[i].result = 1;
            if (jobs[i].result != 1) {
                failures++;
            }
        }

        return failures;
    }

    /* Parallel verification */
    pthread_mutex_lock(&queue_mutex);

    current_kind = PV_JOB_INPUT;
    job_queue = jobs;
    job_count = count;
    jobs_completed = 0;
    next_job = 0;

    /* Wake up all workers */
    pthread_cond_broadcast(&work_available);

    /* Wait for all jobs to complete */
    while (jobs_completed < job_count) {
        pthread_cond_wait(&work_done, &queue_mutex);
    }

    job_queue = NULL;

    pthread_mutex_unlock(&queue_mutex);

    /* Count failures */
    int failures = 0;
    for (int i = 0; i < count; i++) {
        if (jobs[i].result != 1) {
            failures++;
        }
    }

    return failures;
}

/*
 * Get the number of worker threads.
 *
 * @return Number of active workers, or 0 if not initialized
 */
int pv_get_num_workers(void) {
    return initialized ? num_workers : 0;
}

/*
 * Shutdown the worker pool.
 * Call this before exiting to clean up resources.
 */
void pv_shutdown(void) {
    if (!initialized) {
        return;
    }

    /* Signal shutdown */
    pthread_mutex_lock(&queue_mutex);
    shutdown_flag = 1;
    pthread_cond_broadcast(&work_available);
    pthread_mutex_unlock(&queue_mutex);

    /* Join all worker threads */
    for (int i = 0; i < num_workers; i++) {
        if (workers[i].running) {
            pthread_join(workers[i].thread, NULL);
            workers[i].running = 0;
        }
        if (workers[i].ctx) {
            secp256k1_context_destroy(workers[i].ctx);
            workers[i].ctx = NULL;
        }
    }

    free(workers);
    workers = NULL;
    num_workers = 0;
    initialized = 0;
    shutdown_flag = 0;
}

/*
 * Verify a batch of pre-computed signatures in parallel.
 *
 * Lua computes the sighashes (which requires full tx parsing and script
 * handling) and passes them here for parallel ECDSA verification.
 *
 * @param jobs Array of sig_verify_job structures with pubkey, sig, and sighash
 * @param count Number of jobs
 * @return Number of failures (0 = all valid), -1 on error
 */
int pv_verify_signatures(sig_verify_job *jobs, int count) {
    if (!initialized) {
        if (pv_init(0) < 0) {
            return -1;
        }
    }

    if (count <= 0) {
        return 0;
    }

    /* Single-threaded for small batches */
    if (count < MIN_PARALLEL_INPUTS || num_workers <= 1) {
        int failures = 0;
        secp256k1_context *ctx = workers[0].ctx;

        for (int i = 0; i < count; i++) {
            jobs[i].result = verify_ecdsa(
                ctx,
                jobs[i].pubkey, jobs[i].pubkey_len,
                jobs[i].sig_der, jobs[i].sig_len,
                jobs[i].msghash32
            );
            if (jobs[i].result != 1) {
                failures++;
            }
        }

        return failures;
    }

    /* Parallel verification — uses the unified worker pool */
    pthread_mutex_lock(&queue_mutex);

    current_kind = PV_JOB_SIG;
    job_queue = jobs;
    job_count = count;
    jobs_completed = 0;
    next_job = 0;

    pthread_cond_broadcast(&work_available);

    while (jobs_completed < job_count) {
        pthread_cond_wait(&work_done, &queue_mutex);
    }

    job_queue = NULL;

    pthread_mutex_unlock(&queue_mutex);

    int failures = 0;
    for (int i = 0; i < count; i++) {
        if (jobs[i].result != 1) {
            failures++;
        }
    }

    return failures;
}
