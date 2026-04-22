// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t w;
} PQBlock128;

typedef struct {
    PQBlock128 s;
    uint8_t tr;
} PQCorrectionWord;

typedef struct {
    PQBlock128 seed;
    PQCorrectionWord *correction_words;
    size_t correction_word_count;
    uint32_t in_bits;
    uint64_t domain_size;
} PQKeyShare;

typedef struct {
    PQKeyShare left;
    PQKeyShare right;
} PQGeneratedKeys;

int generate_query_key(
    uint64_t index,
    uint64_t domain_size,
    const uint8_t *random_seed_bytes,
    size_t random_seed_len,
    PQGeneratedKeys *out_keys);

void free_generated_query_key(PQGeneratedKeys *keys);

int aggregate_query_share(
    int party,
    const PQKeyShare *key,
    const uint64_t *payload_blocks,
    size_t record_count,
    size_t block_count,
    uint32_t worker_count,
    uint64_t *out_blocks);

int reconstruct_u64_blocks(
    const uint64_t *left_blocks,
    const uint64_t *right_blocks,
    size_t block_count,
    uint64_t *out_blocks);

#ifdef __cplusplus
}
#endif
