// SPDX-License-Identifier: Apache-2.0
#include "pq_dpf_core/c_api.h"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <new>
#include <vector>

#include "pq_dpf_core/core.hpp"

namespace {

using pq::dpf_core::Block128;
using pq::dpf_core::CorrectionWord;
using pq::dpf_core::DpfEngine;
using pq::dpf_core::KeyShare;

Block128 ToCpp(const PQBlock128 &value) {
    return {value.x, value.y, value.z, value.w};
}

PQBlock128 ToC(const Block128 &value) {
    return {value.x, value.y, value.z, value.w};
}

PQCorrectionWord ToC(const CorrectionWord &value) {
    return {ToC(value.s), static_cast<uint8_t>(value.tr ? 1 : 0)};
}

KeyShare ToCpp(const PQKeyShare &value) {
    KeyShare key{
        ToCpp(value.seed),
        {},
        value.in_bits,
        value.domain_size,
    };
    key.correction_words.reserve(value.correction_word_count);
    for (size_t i = 0; i < value.correction_word_count; ++i) {
        const auto &cw = value.correction_words[i];
        key.correction_words.push_back({ToCpp(cw.s), cw.tr != 0});
    }
    return key;
}

void ResetKeyShare(PQKeyShare *value) {
    if (value == nullptr) {
        return;
    }
    if (value->correction_words != nullptr) {
        std::free(value->correction_words);
        value->correction_words = nullptr;
    }
    value->correction_word_count = 0;
    value->in_bits = 0;
    value->domain_size = 0;
    std::memset(&value->seed, 0, sizeof(value->seed));
}

int FillKeyShare(const KeyShare &input, PQKeyShare *output) {
    output->seed = ToC(input.seed);
    output->correction_word_count = input.correction_words.size();
    output->in_bits = input.in_bits;
    output->domain_size = input.domain_size;
    output->correction_words = static_cast<PQCorrectionWord *>(
        std::calloc(input.correction_words.size(), sizeof(PQCorrectionWord)));
    if (output->correction_words == nullptr) {
        ResetKeyShare(output);
        return 1;
    }
    for (size_t i = 0; i < input.correction_words.size(); ++i) {
        output->correction_words[i] = ToC(input.correction_words[i]);
    }
    return 0;
}

}  // namespace

extern "C" int generate_query_key(
    uint64_t index,
    uint64_t domain_size,
    const uint8_t *random_seed_bytes,
    size_t random_seed_len,
    PQGeneratedKeys *out_keys) {
    if (out_keys == nullptr || random_seed_bytes == nullptr || random_seed_len == 0) {
        return 1;
    }

    try {
        DpfEngine engine;
        auto keys = engine.GenerateKey(index, domain_size, {random_seed_bytes, random_seed_len});
        std::memset(out_keys, 0, sizeof(*out_keys));
        if (FillKeyShare(keys.left, &out_keys->left) != 0) {
            free_generated_query_key(out_keys);
            return 1;
        }
        if (FillKeyShare(keys.right, &out_keys->right) != 0) {
            free_generated_query_key(out_keys);
            return 1;
        }
        return 0;
    } catch (...) {
        free_generated_query_key(out_keys);
        return 1;
    }
}

extern "C" void free_generated_query_key(PQGeneratedKeys *keys) {
    if (keys == nullptr) {
        return;
    }
    ResetKeyShare(&keys->left);
    ResetKeyShare(&keys->right);
}

extern "C" int aggregate_query_share(
    int party,
    const PQKeyShare *key,
    const uint64_t *payload_blocks,
    size_t record_count,
    size_t block_count,
    uint32_t worker_count,
    uint64_t *out_blocks) {
    if (key == nullptr || payload_blocks == nullptr || out_blocks == nullptr) {
        return 1;
    }

    try {
        DpfEngine engine;
        auto result = engine.AggregateU64Blocks(
            party != 0,
            ToCpp(*key),
            {payload_blocks, record_count * block_count},
            record_count,
            block_count,
            worker_count);
        for (size_t i = 0; i < result.size(); ++i) {
            out_blocks[i] = result[i];
        }
        return 0;
    } catch (...) {
        return 1;
    }
}

extern "C" int reconstruct_u64_blocks(
    const uint64_t *left_blocks, const uint64_t *right_blocks, size_t block_count, uint64_t *out_blocks) {
    if (left_blocks == nullptr || right_blocks == nullptr || out_blocks == nullptr) {
        return 1;
    }

    try {
        DpfEngine engine;
        auto result = engine.ReconstructU64Blocks({left_blocks, block_count}, {right_blocks, block_count});
        for (size_t i = 0; i < result.size(); ++i) {
            out_blocks[i] = result[i];
        }
        return 0;
    } catch (...) {
        return 1;
    }
}
