/*
 * collision.c
 *
 * Simple experiments to measure:
 *  - Weak collision resistance (second-preimage): find m' != m such that H24(m') == H24(m)
 *  - Strong collision resistance (birthday): find any pair m1 != m2 with H24(m1) == H24(m2)
 *
 * Implementation notes:
 *  - Uses OpenSSL EVP digest API (EVP_DigestInit_ex, EVP_DigestUpdate, EVP_DigestFinal_ex)
 *  - Uses SHA-256 and truncates to first 24 bits (3 bytes)
 *  - Generates random messages via OpenSSL RAND_bytes()
 *
 * Compile:
 *   make
 *
 * Run example:
 *   ./collision_experiment
 *
 * Output:
 *   weak_results.csv   (per-trial attempts for weak test)
 *   strong_results.csv (per-trial attempts for strong test)
 *
 * Defaults:
 *   WEAK_TRIALS = 10
 *   STRONG_TRIALS = 100
 *   MSG_LEN = 16 bytes
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* Configuration: adjust as needed */
#define WEAK_TRIALS    10     /* number of independent weak-preimage trials */
#define STRONG_TRIALS  100    /* number of independent birthday (strong) trials */
#define MSG_LEN        16     /* message length in bytes */
#define HASH_TRUNC_BYTES 3    /* we use first 3 bytes (24 bits) */

typedef uint32_t hash24_t;

/* Utility: returns current time in seconds (double) */
static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Compute SHA-256 of (data,len) and return the first 24 bits as uint32 (lower 24 bits used) */
static int compute_truncated24_sha256(const unsigned char *data, size_t len, hash24_t *out) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) { EVP_MD_CTX_free(ctx); return 0; }
    if (EVP_DigestUpdate(ctx, data, len) != 1) { EVP_MD_CTX_free(ctx); return 0; }
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) { EVP_MD_CTX_free(ctx); return 0; }
    EVP_MD_CTX_free(ctx);
    /* Build 24-bit value from first 3 bytes (big-endian style) */
    *out = ((uint32_t)digest[0] << 16) | ((uint32_t)digest[1] << 8) | ((uint32_t)digest[2]);
    return 1;
}

/* Generate random message using OpenSSL RAND_bytes */
static int gen_random_msg(unsigned char *buf, size_t len) {
    if (RAND_bytes(buf, (int)len) != 1) return 0;
    return 1;
}

/* Compare two messages (len bytes). Return 1 if equal, 0 otherwise */
static int msg_equal(const unsigned char *a, const unsigned char *b, size_t len) {
    return memcmp(a, b, len) == 0;
}

/* -------- Weak collision experiment (single trial) --------
 * Given a fixed target message 'm' and its truncated hash 'h_target',
 * repeatedly generate random candidate messages m' until we find
 * m' != m and truncated_hash(m') == h_target.
 * Returns the number of candidate hashes computed (attempts).
 */
static unsigned long weak_single_trial(const unsigned char *m, size_t mlen, hash24_t h_target) {
    unsigned char cand[MSG_LEN];
    hash24_t h;
    unsigned long attempts = 0;

    while (1) {
        if (!gen_random_msg(cand, mlen)) {
            fprintf(stderr, "RAND_bytes failed\n");
            exit(1);
        }
        /* Ensure candidate differs from original */
        if (msg_equal(m, cand, mlen)) continue;

        if (!compute_truncated24_sha256(cand, mlen, &h)) {
            fprintf(stderr, "hash failed\n");
            exit(1);
        }
        attempts++;
        if (h == h_target) {
            return attempts;
        }
    }
}

/* -------- Strong collision experiment (single trial) --------
 * Generate random messages and store their truncated hashes in a simple hash table,
 * checking for collision (same truncated hash but different message).
 * Returns number of hashes computed (attempts) until first collision found.
 *
 * We implement a simple chained hash table with fixed BUCKETS for clarity and speed.
 */

#define BUCKETS 8192  /* must be power of two and sufficiently larger than expected 4096 */
typedef struct Node {
    hash24_t h;
    unsigned char msg[MSG_LEN];
    struct Node *next;
} Node;

static unsigned long strong_single_trial(void) {
    Node *table[BUCKETS];
    memset(table, 0, sizeof(table));
    unsigned long attempts = 0;

    while (1) {
        unsigned char m[MSG_LEN];
        hash24_t h;
        if (!gen_random_msg(m, MSG_LEN)) { fprintf(stderr, "RAND_bytes failed\n"); exit(1); }
        if (!compute_truncated24_sha256(m, MSG_LEN, &h)) { fprintf(stderr, "hash failed\n"); exit(1); }

        attempts++;
        size_t idx = (size_t)(h & (BUCKETS - 1)); /* simple modulo via mask */

        /* Search bucket for matching hash but different message */
        Node *cur = table[idx];
        while (cur) {
            if (cur->h == h) {
                if (!msg_equal(cur->msg, m, MSG_LEN)) {
                    /* found collision */
                    /* cleanup table */
                    for (size_t i = 0; i < BUCKETS; ++i) {
                        Node *n = table[i];
                        while (n) { Node *t = n; n = n->next; free(t); }
                    }
                    return attempts;
                }
                /* else same message -> continue */
            }
            cur = cur->next;
        }
        /* Not found: insert new node to bucket */
        Node *node = (Node*)malloc(sizeof(Node));
        if (!node) { fprintf(stderr, "malloc failed\n"); exit(1); }
        node->h = h;
        memcpy(node->msg, m, MSG_LEN);
        node->next = table[idx];
        table[idx] = node;
    }
}

/* Statistics helper: compute average from array */
static double average(unsigned long *arr, size_t n) {
    unsigned long sum = 0;
    for (size_t i = 0; i < n; ++i) sum += arr[i];
    return (double)sum / (double)n;
}

/* main: orchestrate experiments and save results */
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    printf("Collision experiment (truncated 24-bit SHA-256)\n");
    printf("Configuration: WEAK_TRIALS=%d STRONG_TRIALS=%d MSG_LEN=%d\n", WEAK_TRIALS, STRONG_TRIALS, MSG_LEN);

    /* Seed OpenSSL RNG (usually initialized), but do one RAND_poll implicitly by generating bytes below */
    unsigned char seedtest[1];
    if (!RAND_bytes(seedtest, 1)) {
        fprintf(stderr, "RAND_bytes initialization failed\n");
        return 1;
    }

    /* Arrays to store per-trial attempt counts */
    unsigned long *weak_counts = (unsigned long*)malloc(sizeof(unsigned long) * WEAK_TRIALS);
    unsigned long *strong_counts = (unsigned long*)malloc(sizeof(unsigned long) * STRONG_TRIALS);
    if (!weak_counts || !strong_counts) { fprintf(stderr, "malloc failed\n"); return 1; }

    /* ---------- Weak trials ---------- */
    printf("Running %d weak (second-preimage) trials...\n", WEAK_TRIALS);
    double t0 = now_seconds();
    for (int t = 0; t < WEAK_TRIALS; ++t) {
        unsigned char m[MSG_LEN];
        if (!gen_random_msg(m, MSG_LEN)) { fprintf(stderr, "RAND_bytes failed\n"); return 1; }
        hash24_t target;
        if (!compute_truncated24_sha256(m, MSG_LEN, &target)) { fprintf(stderr, "hash failed\n"); return 1; }

        unsigned long attempts = weak_single_trial(m, MSG_LEN, target);
        weak_counts[t] = attempts;
        printf(" weak trial %3d: %10lu attempts\n", t+1, attempts);
    }
    double t1 = now_seconds();
    printf("Weak trials done (elapsed %.2f s). Avg attempts = %.2f\n", t1 - t0, average(weak_counts, WEAK_TRIALS));

    /* Save weak results to CSV */
    FILE *fw = fopen("weak_results.csv", "w");
    if (fw) {
        fprintf(fw, "trial,attempts\n");
        for (int t = 0; t < WEAK_TRIALS; ++t) fprintf(fw, "%d,%lu\n", t+1, weak_counts[t]);
        fclose(fw);
    } else {
        fprintf(stderr, "Warning: could not write weak_results.csv\n");
    }

    /* ---------- Strong trials ---------- */
    printf("Running %d strong (birthday) trials...\n", STRONG_TRIALS);
    t0 = now_seconds();
    for (int t = 0; t < STRONG_TRIALS; ++t) {
        unsigned long attempts = strong_single_trial();
        strong_counts[t] = attempts;
        printf(" strong trial %3d: %6lu attempts\n", t+1, attempts);
    }
    t1 = now_seconds();
    printf("Strong trials done (elapsed %.2f s). Avg attempts = %.2f\n", t1 - t0, average(strong_counts, STRONG_TRIALS));

    /* Save strong results to CSV */
    FILE *fs = fopen("strong_results.csv", "w");
    if (fs) {
        fprintf(fs, "trial,attempts\n");
        for (int t = 0; t < STRONG_TRIALS; ++t) fprintf(fs, "%d,%lu\n", t+1, strong_counts[t]);
        fclose(fs);
    } else {
        fprintf(stderr, "Warning: could not write strong_results.csv\n");
    }

    /* Print summary (averages) */
    printf("\nSummary:\n");
    printf("  Weak avg attempts   = %.2f (theoretical ~ 2^24 = 16777216)\n", average(weak_counts, WEAK_TRIALS));
    printf("  Strong avg attempts = %.2f (theoretical ~ 2^(24/2) = 4096)\n", average(strong_counts, STRONG_TRIALS));

    free(weak_counts);
    free(strong_counts);
    return 0;
}
