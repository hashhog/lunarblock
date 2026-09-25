/*
 * coin_prefetch.c — parallel point reads of a block's coins from RocksDB.
 *
 * WHY. Profiling live R4 range slices (2026-09-24, 650000->675000) showed the
 * single validation thread spending ~58% of its wall time blocked in
 * pread64() under rocksdb_get_cf: ConnectBlock's per-input coin fetch
 * (CoinView:get) and per-output FRESH probe (CoinView:add) each issue one
 * synchronous RocksDB Get, one after another, so a block with ~5k inputs and
 * ~5k outputs pays ~10k serial disk round trips while 15 script workers sit
 * idle. Core hides most of this latency with a large in-memory
 * CCoinsViewCache (coins.cpp, sized by -dbcache); lunarblock's CoinView cannot
 * hold 67M+ coins in Lua tables, so we issue the block's reads up front, in
 * parallel, instead. The lookups themselves are the same ones Core's
 * ConnectBlock makes through view.AccessCoin / HaveCoin (validation.cpp).
 *
 * WHAT. coin_prefetch_get() performs n independent rocksdb_get_cf() calls
 * spread over up to nthreads short-lived pthreads. RocksDB's DB::Get is
 * thread-safe (concurrent readers are the supported mode). The results are
 * handed back to the single Lua thread, which alone decides what to do with
 * them. This file makes NO consensus decision: it returns raw bytes (or
 * "absent", or "error"), exactly what a serial rocksdb_get_cf() would have
 * returned at the same point in time — nothing writes the DB while it runs
 * (the Lua thread is blocked inside this call).
 *
 * RESULT CONTRACT (per key i):
 *   vals[i] != NULL, lens[i] = value length   -> present (caller rocksdb_free)
 *   vals[i] == NULL, lens[i] = 0              -> absent
 *   vals[i] == NULL, lens[i] = (size_t)-1     -> RocksDB error; the caller
 *       must NOT treat the key as absent (it falls back to its serial Get,
 *       which will surface the same error on the verdict-bearing path).
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <rocksdb/c.h>

typedef struct {
    rocksdb_t *db;
    const rocksdb_readoptions_t *ro;
    rocksdb_column_family_handle_t *cf;
    const char *keys;
    size_t keylen;
    int n;
    char **vals;
    size_t *lens;
    int next;               /* shared work index, taken with __atomic ops */
} prefetch_job_t;

static void do_range(prefetch_job_t *j)
{
    for (;;) {
        int i = __atomic_fetch_add(&j->next, 1, __ATOMIC_RELAXED);
        if (i >= j->n) break;
        char *err = NULL;
        size_t vlen = 0;
        char *v = rocksdb_get_cf(j->db, j->ro, j->cf,
                                 j->keys + (size_t)i * j->keylen, j->keylen,
                                 &vlen, &err);
        if (err != NULL) {
            rocksdb_free(err);
            if (v) rocksdb_free(v);
            j->vals[i] = NULL;
            j->lens[i] = (size_t)-1;
        } else {
            j->vals[i] = v;
            j->lens[i] = v ? vlen : 0;
        }
    }
}

static void *worker(void *arg)
{
    do_range((prefetch_job_t *)arg);
    return NULL;
}

#define PREFETCH_MAX_THREADS 64

/* Returns the number of threads used (>= 1). */
int coin_prefetch_get(rocksdb_t *db, const rocksdb_readoptions_t *ro,
                      rocksdb_column_family_handle_t *cf,
                      const char *keys, size_t keylen, int n,
                      char **vals, size_t *lens, int nthreads)
{
    prefetch_job_t j;
    j.db = db; j.ro = ro; j.cf = cf;
    j.keys = keys; j.keylen = keylen; j.n = n;
    j.vals = vals; j.lens = lens; j.next = 0;
    if (n <= 0) return 1;

    if (nthreads > PREFETCH_MAX_THREADS) nthreads = PREFETCH_MAX_THREADS;
    /* Not worth a thread for fewer than ~16 keys each. */
    int want = (n + 15) / 16;
    if (nthreads > want) nthreads = want;
    if (nthreads < 1) nthreads = 1;

    pthread_t tids[PREFETCH_MAX_THREADS];
    int started = 0;
    for (int t = 1; t < nthreads; t++) {
        if (pthread_create(&tids[started], NULL, worker, &j) != 0) break;
        started++;
    }
    do_range(&j);           /* calling thread works too */
    for (int t = 0; t < started; t++) pthread_join(tids[t], NULL);
    return started + 1;
}
