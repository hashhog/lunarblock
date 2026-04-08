/*
 * hdog_import.c - Fast HDOG UTXO snapshot importer for lunarblock
 *
 * Reads the HDOG binary format and writes directly to RocksDB via its C API,
 * avoiding per-UTXO Lua overhead for 165M+ entries.
 *
 * Compile: gcc -O2 -shared -fPIC -o lib/hdog_import.so csrc/hdog_import.c -lrocksdb
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>

/* RocksDB C API forward declarations (we link against librocksdb) */
typedef struct rocksdb_t rocksdb_t;
typedef struct rocksdb_options_t rocksdb_options_t;
typedef struct rocksdb_readoptions_t rocksdb_readoptions_t;
typedef struct rocksdb_writeoptions_t rocksdb_writeoptions_t;
typedef struct rocksdb_writebatch_t rocksdb_writebatch_t;
typedef struct rocksdb_column_family_handle_t rocksdb_column_family_handle_t;
typedef struct rocksdb_block_based_table_options_t rocksdb_block_based_table_options_t;
typedef struct rocksdb_cache_t rocksdb_cache_t;

extern rocksdb_options_t* rocksdb_options_create(void);
extern void rocksdb_options_destroy(rocksdb_options_t*);
extern void rocksdb_options_set_create_if_missing(rocksdb_options_t*, unsigned char);
extern void rocksdb_options_set_create_missing_column_families(rocksdb_options_t*, unsigned char);
extern void rocksdb_options_set_max_open_files(rocksdb_options_t*, int);
extern void rocksdb_options_set_write_buffer_size(rocksdb_options_t*, size_t);
extern void rocksdb_options_set_max_write_buffer_number(rocksdb_options_t*, int);
extern void rocksdb_options_set_compression(rocksdb_options_t*, int);
extern void rocksdb_options_set_block_based_table_factory(rocksdb_options_t*, rocksdb_block_based_table_options_t*);

extern rocksdb_block_based_table_options_t* rocksdb_block_based_options_create(void);
extern void rocksdb_block_based_options_destroy(rocksdb_block_based_table_options_t*);
extern void rocksdb_block_based_options_set_block_cache(rocksdb_block_based_table_options_t*, rocksdb_cache_t*);
extern void rocksdb_block_based_options_set_block_size(rocksdb_block_based_table_options_t*, size_t);
extern rocksdb_cache_t* rocksdb_cache_create_lru(size_t);
extern void rocksdb_cache_destroy(rocksdb_cache_t*);

extern rocksdb_t* rocksdb_open_column_families(
    const rocksdb_options_t*, const char*, int,
    const char* const*, const rocksdb_options_t* const*,
    rocksdb_column_family_handle_t**, char**);
extern void rocksdb_close(rocksdb_t*);
extern void rocksdb_column_family_handle_destroy(rocksdb_column_family_handle_t*);
extern char** rocksdb_list_column_families(const rocksdb_options_t*, const char*, size_t*, char**);
extern void rocksdb_list_column_families_destroy(char**, size_t);

extern rocksdb_writeoptions_t* rocksdb_writeoptions_create(void);
extern void rocksdb_writeoptions_destroy(rocksdb_writeoptions_t*);
extern void rocksdb_writeoptions_set_sync(rocksdb_writeoptions_t*, unsigned char);
/* rocksdb_writeoptions_set_disable_WAL may not be available in all versions */

extern rocksdb_writebatch_t* rocksdb_writebatch_create(void);
extern void rocksdb_writebatch_destroy(rocksdb_writebatch_t*);
extern void rocksdb_writebatch_clear(rocksdb_writebatch_t*);
extern void rocksdb_writebatch_put_cf(rocksdb_writebatch_t*,
    rocksdb_column_family_handle_t*, const char*, size_t, const char*, size_t);
extern void rocksdb_writebatch_put(rocksdb_writebatch_t*,
    const char*, size_t, const char*, size_t);
extern void rocksdb_write(rocksdb_t*, const rocksdb_writeoptions_t*,
    rocksdb_writebatch_t*, char**);

extern void rocksdb_put_cf(rocksdb_t*, const rocksdb_writeoptions_t*,
    rocksdb_column_family_handle_t*, const char*, size_t, const char*, size_t, char**);
extern void rocksdb_put(rocksdb_t*, const rocksdb_writeoptions_t*,
    const char*, size_t, const char*, size_t, char**);
extern void rocksdb_free(void*);

/* HDOG header: 52 bytes */
#define HDOG_MAGIC "HDOG"
#define HDOG_HEADER_SIZE 52

/* Read buffer size: 64MB for large sequential reads */
#define READ_BUF_SIZE (64 * 1024 * 1024)

/* Batch size: flush every N UTXOs */
#define BATCH_SIZE 100000

/* Progress report interval */
#define PROGRESS_INTERVAL 1000000

/*
 * UTXO value format (matching lunarblock's serialize_utxo_entry):
 *   int64 LE  - value (satoshis)
 *   varint    - script length
 *   bytes     - script_pubkey
 *   uint32 LE - height
 *   uint8     - is_coinbase (0 or 1)
 *
 * Max value size: 8 + 5 + 10000 + 4 + 1 = ~10018 bytes
 */
#define MAX_VALUE_SIZE 16384

/* Write a Bitcoin varint into buf, return number of bytes written */
static int write_varint(uint8_t *buf, uint64_t val) {
    if (val < 0xFD) {
        buf[0] = (uint8_t)val;
        return 1;
    } else if (val <= 0xFFFF) {
        buf[0] = 0xFD;
        buf[1] = (uint8_t)(val & 0xFF);
        buf[2] = (uint8_t)((val >> 8) & 0xFF);
        return 3;
    } else if (val <= 0xFFFFFFFF) {
        buf[0] = 0xFE;
        buf[1] = (uint8_t)(val & 0xFF);
        buf[2] = (uint8_t)((val >> 8) & 0xFF);
        buf[3] = (uint8_t)((val >> 16) & 0xFF);
        buf[4] = (uint8_t)((val >> 24) & 0xFF);
        return 5;
    } else {
        buf[0] = 0xFF;
        for (int i = 0; i < 8; i++)
            buf[1 + i] = (uint8_t)((val >> (i * 8)) & 0xFF);
        return 9;
    }
}

/* Buffered file reader */
typedef struct {
    FILE *fp;
    uint8_t *buf;
    size_t buf_size;
    size_t buf_pos;
    size_t buf_len;
    uint64_t total_read;
} buffered_reader_t;

static int br_init(buffered_reader_t *br, const char *path) {
    br->fp = fopen(path, "rb");
    if (!br->fp) return -1;
    br->buf = (uint8_t *)malloc(READ_BUF_SIZE);
    if (!br->buf) { fclose(br->fp); return -1; }
    br->buf_size = READ_BUF_SIZE;
    br->buf_pos = 0;
    br->buf_len = 0;
    br->total_read = 0;
    return 0;
}

static void br_free(buffered_reader_t *br) {
    if (br->fp) fclose(br->fp);
    if (br->buf) free(br->buf);
    br->fp = NULL;
    br->buf = NULL;
}

/* Read exactly n bytes from buffered reader. Returns 0 on success, -1 on EOF/error. */
static int br_read(buffered_reader_t *br, void *dst, size_t n) {
    uint8_t *out = (uint8_t *)dst;
    size_t remaining = n;

    while (remaining > 0) {
        size_t avail = br->buf_len - br->buf_pos;
        if (avail > 0) {
            size_t chunk = avail < remaining ? avail : remaining;
            memcpy(out, br->buf + br->buf_pos, chunk);
            br->buf_pos += chunk;
            out += chunk;
            remaining -= chunk;
        } else {
            /* Refill buffer */
            br->buf_len = fread(br->buf, 1, br->buf_size, br->fp);
            br->buf_pos = 0;
            if (br->buf_len == 0) return -1;  /* EOF or error */
        }
    }
    br->total_read += n;
    return 0;
}

/* Result struct returned to Lua via FFI */
typedef struct {
    int success;
    char error_msg[256];
    uint64_t utxo_count;
    uint32_t block_height;
    uint8_t block_hash[32];
    double elapsed_seconds;
} hdog_import_result_t;

/*
 * Main import function - called from Lua via FFI.
 *
 * Opens its own RocksDB handle to the chainstate directory,
 * imports all UTXOs, sets chain tip metadata, and closes.
 */
hdog_import_result_t hdog_import(
    const char *hdog_path,
    const char *db_path,
    int cache_mb
) {
    hdog_import_result_t result;
    memset(&result, 0, sizeof(result));

    struct timespec ts_start, ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    /* Open HDOG file with buffered reader */
    buffered_reader_t br;
    if (br_init(&br, hdog_path) != 0) {
        result.success = 0;
        snprintf(result.error_msg, sizeof(result.error_msg),
                 "Cannot open HDOG file: %s: %s", hdog_path, strerror(errno));
        return result;
    }

    /* Read and validate header (52 bytes) */
    uint8_t header[HDOG_HEADER_SIZE];
    if (br_read(&br, header, HDOG_HEADER_SIZE) != 0) {
        result.success = 0;
        snprintf(result.error_msg, sizeof(result.error_msg), "Cannot read HDOG header");
        br_free(&br);
        return result;
    }

    /* Validate magic */
    if (memcmp(header, HDOG_MAGIC, 4) != 0) {
        result.success = 0;
        snprintf(result.error_msg, sizeof(result.error_msg),
                 "Invalid magic: expected HDOG, got %c%c%c%c",
                 header[0], header[1], header[2], header[3]);
        br_free(&br);
        return result;
    }

    /* Parse header fields */
    uint32_t version = header[4] | (header[5] << 8) | (header[6] << 16) | (header[7] << 24);
    if (version != 1) {
        result.success = 0;
        snprintf(result.error_msg, sizeof(result.error_msg),
                 "Unsupported HDOG version: %u", version);
        br_free(&br);
        return result;
    }

    /* Block hash: 32 bytes at offset 8, little-endian */
    memcpy(result.block_hash, header + 8, 32);

    /* Block height: uint32 LE at offset 40 */
    uint32_t block_height = header[40] | (header[41] << 8) | (header[42] << 16) | (header[43] << 24);
    result.block_height = block_height;

    /* UTXO count: uint64 LE at offset 44 */
    uint64_t utxo_count = 0;
    for (int i = 0; i < 8; i++)
        utxo_count |= ((uint64_t)header[44 + i]) << (i * 8);
    result.utxo_count = utxo_count;

    fprintf(stdout, "HDOG snapshot: version=%u height=%u utxo_count=%lu\n",
            version, block_height, (unsigned long)utxo_count);
    fflush(stdout);

    /* Open RocksDB */
    char *errptr = NULL;

    rocksdb_options_t *opts = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(opts, 1);
    rocksdb_options_set_create_missing_column_families(opts, 1);
    rocksdb_options_set_max_open_files(opts, 1000);
    rocksdb_options_set_write_buffer_size(opts, 256ULL * 1024 * 1024);  /* 256MB write buffer */
    rocksdb_options_set_max_write_buffer_number(opts, 4);
    rocksdb_options_set_compression(opts, 0);  /* No compression */

    rocksdb_block_based_table_options_t *table_opts = rocksdb_block_based_options_create();
    size_t cache_bytes = (size_t)cache_mb * 1024 * 1024;
    rocksdb_cache_t *cache = rocksdb_cache_create_lru(cache_bytes);
    rocksdb_block_based_options_set_block_cache(table_opts, cache);
    rocksdb_block_based_options_set_block_size(table_opts, 16 * 1024);
    rocksdb_options_set_block_based_table_factory(opts, table_opts);

    /* List existing column families */
    size_t num_cf = 0;
    char **cf_list = rocksdb_list_column_families(opts, db_path, &num_cf, &errptr);
    if (errptr) {
        /* DB doesn't exist yet, use defaults */
        rocksdb_free(errptr);
        errptr = NULL;
        num_cf = 0;
    }

    /* Column family names we need */
    const char *all_cf_names[] = {
        "default", "headers", "blocks", "utxo", "tx_index",
        "height", "meta", "undo", "block_filter", "filter_height"
    };
    int all_cf_count = 10;

    /* Merge existing + required CFs */
    const char **open_cf_names;
    int open_cf_count;

    if (num_cf > 0) {
        /* Use existing list, they should contain all we need */
        open_cf_names = (const char **)cf_list;
        open_cf_count = (int)num_cf;
    } else {
        open_cf_names = all_cf_names;
        open_cf_count = all_cf_count;
    }

    rocksdb_options_t **cf_opts = (rocksdb_options_t **)malloc(sizeof(rocksdb_options_t *) * open_cf_count);
    rocksdb_column_family_handle_t **cf_handles =
        (rocksdb_column_family_handle_t **)malloc(sizeof(rocksdb_column_family_handle_t *) * open_cf_count);
    for (int i = 0; i < open_cf_count; i++)
        cf_opts[i] = opts;

    rocksdb_t *db = rocksdb_open_column_families(
        opts, db_path, open_cf_count, open_cf_names, (const rocksdb_options_t *const *)cf_opts,
        cf_handles, &errptr);

    if (errptr) {
        result.success = 0;
        snprintf(result.error_msg, sizeof(result.error_msg), "RocksDB open error: %s", errptr);
        rocksdb_free(errptr);
        br_free(&br);
        free(cf_opts);
        free(cf_handles);
        if (cf_list) rocksdb_list_column_families_destroy(cf_list, num_cf);
        rocksdb_block_based_options_destroy(table_opts);
        rocksdb_cache_destroy(cache);
        rocksdb_options_destroy(opts);
        return result;
    }

    /* Find the UTXO and META column family handles */
    rocksdb_column_family_handle_t *utxo_cf = NULL;
    rocksdb_column_family_handle_t *meta_cf = NULL;
    rocksdb_column_family_handle_t *height_cf = NULL;

    for (int i = 0; i < open_cf_count; i++) {
        if (strcmp(open_cf_names[i], "utxo") == 0) utxo_cf = cf_handles[i];
        else if (strcmp(open_cf_names[i], "meta") == 0) meta_cf = cf_handles[i];
        else if (strcmp(open_cf_names[i], "height") == 0) height_cf = cf_handles[i];
    }

    if (!utxo_cf || !meta_cf || !height_cf) {
        result.success = 0;
        snprintf(result.error_msg, sizeof(result.error_msg),
                 "Missing column families: utxo=%p meta=%p height=%p",
                 (void*)utxo_cf, (void*)meta_cf, (void*)height_cf);
        for (int i = 0; i < open_cf_count; i++)
            rocksdb_column_family_handle_destroy(cf_handles[i]);
        rocksdb_close(db);
        br_free(&br);
        free(cf_opts);
        free(cf_handles);
        if (cf_list) rocksdb_list_column_families_destroy(cf_list, num_cf);
        rocksdb_block_based_options_destroy(table_opts);
        rocksdb_cache_destroy(cache);
        rocksdb_options_destroy(opts);
        return result;
    }

    /* Write options: disable sync for bulk import, disable WAL for speed */
    rocksdb_writeoptions_t *write_opts = rocksdb_writeoptions_create();
    rocksdb_writeoptions_set_sync(write_opts, 0);

    /* Create write batch */
    rocksdb_writebatch_t *batch = rocksdb_writebatch_create();

    /* Buffers for key and value construction */
    uint8_t key_buf[36];   /* 32 txid + 4 vout */
    uint8_t val_buf[MAX_VALUE_SIZE];
    uint8_t utxo_buf[32 + 4 + 8 + 4 + 2];  /* fixed part of each UTXO record: 50 bytes */

    uint64_t imported = 0;
    uint64_t batch_count = 0;

    fprintf(stdout, "Starting UTXO import: %lu entries...\n", (unsigned long)utxo_count);
    fflush(stdout);

    for (uint64_t i = 0; i < utxo_count; i++) {
        /* Read fixed-size part: txid(32) + vout(4) + amount(8) + height_cb(4) + script_len(2) = 50 bytes */
        if (br_read(&br, utxo_buf, 50) != 0) {
            result.success = 0;
            snprintf(result.error_msg, sizeof(result.error_msg),
                     "Unexpected EOF at UTXO %lu of %lu", (unsigned long)i, (unsigned long)utxo_count);
            goto cleanup;
        }

        /* Key: txid (32 bytes) + vout (4 bytes LE) */
        memcpy(key_buf, utxo_buf, 36);  /* txid + vout already in LE */

        /* Parse fields from the fixed part */
        /* amount: int64 LE at offset 36 */
        /* height_cb: uint32 LE at offset 44 */
        /* script_len: uint16 LE at offset 48 */
        uint16_t script_len = utxo_buf[48] | (utxo_buf[49] << 8);

        /* Build value: matches lunarblock serialize_utxo_entry format:
         *   int64 LE  (amount/value) - 8 bytes
         *   varint    (script length)
         *   bytes     (script_pubkey)
         *   uint32 LE (height)
         *   uint8     (is_coinbase)
         */
        int val_pos = 0;

        /* Copy amount (int64 LE) from utxo_buf offset 36 */
        memcpy(val_buf + val_pos, utxo_buf + 36, 8);
        val_pos += 8;

        /* Write script length as varint */
        val_pos += write_varint(val_buf + val_pos, script_len);

        /* Read script bytes directly into value buffer */
        if (script_len > 0) {
            if (script_len > MAX_VALUE_SIZE - val_pos - 5) {
                result.success = 0;
                snprintf(result.error_msg, sizeof(result.error_msg),
                         "Script too large: %u bytes at UTXO %lu", script_len, (unsigned long)i);
                goto cleanup;
            }
            if (br_read(&br, val_buf + val_pos, script_len) != 0) {
                result.success = 0;
                snprintf(result.error_msg, sizeof(result.error_msg),
                         "Unexpected EOF reading script at UTXO %lu", (unsigned long)i);
                goto cleanup;
            }
            val_pos += script_len;
        }

        /* Decode height and coinbase from height_cb field:
         * height in bits [31:1], coinbase flag in bit [0] */
        uint32_t height_cb = utxo_buf[44] | (utxo_buf[45] << 8) |
                             (utxo_buf[46] << 16) | (utxo_buf[47] << 24);
        uint32_t height = height_cb >> 1;
        uint8_t is_coinbase = height_cb & 1;

        /* Write height as uint32 LE */
        val_buf[val_pos++] = (uint8_t)(height & 0xFF);
        val_buf[val_pos++] = (uint8_t)((height >> 8) & 0xFF);
        val_buf[val_pos++] = (uint8_t)((height >> 16) & 0xFF);
        val_buf[val_pos++] = (uint8_t)((height >> 24) & 0xFF);

        /* Write is_coinbase as uint8 */
        val_buf[val_pos++] = is_coinbase;

        /* Add to batch */
        rocksdb_writebatch_put_cf(batch, utxo_cf,
                                  (const char *)key_buf, 36,
                                  (const char *)val_buf, val_pos);
        batch_count++;

        /* Flush batch every BATCH_SIZE entries */
        if (batch_count >= BATCH_SIZE) {
            rocksdb_write(db, write_opts, batch, &errptr);
            if (errptr) {
                result.success = 0;
                snprintf(result.error_msg, sizeof(result.error_msg),
                         "RocksDB write error at UTXO %lu: %s", (unsigned long)i, errptr);
                rocksdb_free(errptr);
                goto cleanup;
            }
            rocksdb_writebatch_clear(batch);
            batch_count = 0;
        }

        imported++;

        /* Progress report */
        if (imported % PROGRESS_INTERVAL == 0) {
            clock_gettime(CLOCK_MONOTONIC, &ts_now);
            double elapsed = (ts_now.tv_sec - ts_start.tv_sec) +
                            (ts_now.tv_nsec - ts_start.tv_nsec) / 1e9;
            double rate = imported / elapsed;
            double pct = (100.0 * imported) / utxo_count;
            double eta = (utxo_count - imported) / rate;
            fprintf(stdout, "  imported %luM / %luM UTXOs (%.1f%%) - %.0f/s - ETA %.0fs\n",
                    (unsigned long)(imported / 1000000),
                    (unsigned long)(utxo_count / 1000000),
                    pct, rate, eta);
            fflush(stdout);
        }
    }

    /* Flush remaining batch */
    if (batch_count > 0) {
        rocksdb_write(db, write_opts, batch, &errptr);
        if (errptr) {
            result.success = 0;
            snprintf(result.error_msg, sizeof(result.error_msg),
                     "RocksDB final write error: %s", errptr);
            rocksdb_free(errptr);
            goto cleanup;
        }
    }

    /* Set chain tip in META column family.
     * Format: block_hash (32 bytes) + height (uint32 LE) = 36 bytes
     * Key: "chain_tip" */
    {
        uint8_t tip_val[36];
        memcpy(tip_val, result.block_hash, 32);
        tip_val[32] = (uint8_t)(block_height & 0xFF);
        tip_val[33] = (uint8_t)((block_height >> 8) & 0xFF);
        tip_val[34] = (uint8_t)((block_height >> 16) & 0xFF);
        tip_val[35] = (uint8_t)((block_height >> 24) & 0xFF);

        rocksdb_writebatch_clear(batch);
        rocksdb_writebatch_put_cf(batch, meta_cf,
                                  "chain_tip", 9,
                                  (const char *)tip_val, 36);

        /* Also set height index: height (4 bytes BE) -> block_hash */
        uint8_t height_key[4];
        height_key[0] = (uint8_t)((block_height >> 24) & 0xFF);
        height_key[1] = (uint8_t)((block_height >> 16) & 0xFF);
        height_key[2] = (uint8_t)((block_height >> 8) & 0xFF);
        height_key[3] = (uint8_t)(block_height & 0xFF);

        rocksdb_writebatch_put_cf(batch, height_cf,
                                  (const char *)height_key, 4,
                                  (const char *)result.block_hash, 32);

        /* Write with sync to ensure durability */
        rocksdb_writeoptions_t *sync_opts = rocksdb_writeoptions_create();
        rocksdb_writeoptions_set_sync(sync_opts, 1);
        rocksdb_write(db, sync_opts, batch, &errptr);
        rocksdb_writeoptions_destroy(sync_opts);

        if (errptr) {
            result.success = 0;
            snprintf(result.error_msg, sizeof(result.error_msg),
                     "RocksDB error writing chain tip: %s", errptr);
            rocksdb_free(errptr);
            goto cleanup;
        }
    }

    result.success = 1;

    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    result.elapsed_seconds = (ts_now.tv_sec - ts_start.tv_sec) +
                            (ts_now.tv_nsec - ts_start.tv_nsec) / 1e9;

    fprintf(stdout, "Import complete: %lu UTXOs in %.1f seconds (%.0f UTXOs/s)\n",
            (unsigned long)imported, result.elapsed_seconds,
            imported / result.elapsed_seconds);
    fprintf(stdout, "Chain tip set to height %u\n", block_height);
    fflush(stdout);

cleanup:
    rocksdb_writebatch_destroy(batch);
    rocksdb_writeoptions_destroy(write_opts);
    for (int i = 0; i < open_cf_count; i++)
        rocksdb_column_family_handle_destroy(cf_handles[i]);
    rocksdb_close(db);
    br_free(&br);
    free(cf_opts);
    free(cf_handles);
    if (cf_list) rocksdb_list_column_families_destroy(cf_list, num_cf);
    rocksdb_block_based_options_destroy(table_opts);
    rocksdb_cache_destroy(cache);
    rocksdb_options_destroy(opts);

    return result;
}
