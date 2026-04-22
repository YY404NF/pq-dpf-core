// SPDX-License-Identifier: Apache-2.0
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "pq_dpf_core/c_api.h"
#include "pq_dpf_core/core.hpp"

using pq::dpf_core::DpfEngine;

namespace {

void Require(bool cond, const char *message) {
    if (!cond) {
        std::fprintf(stderr, "test failure: %s\n", message);
        std::exit(1);
    }
}

}  // namespace

int main() {
    DpfEngine engine;

    const std::array<uint8_t, 32> random = {
        0x10, 0x22, 0x34, 0x46, 0x58, 0x6a, 0x7c, 0x8e, 0x90, 0xa2, 0xb4, 0xc6, 0xd8, 0xea, 0xfc, 0x0e,
        0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d, 0x8f, 0x91, 0xa3, 0xb5, 0xc7, 0xd9, 0xeb, 0xfd, 0x0f,
    };
    constexpr uint64_t kDomainSize = 32;
    constexpr uint64_t kAlpha = 11;
    auto keys = engine.GenerateKey(kAlpha, kDomainSize, random);

    Require(engine.Eval(false, keys.left, kAlpha) + engine.Eval(true, keys.right, kAlpha) == 1, "point reconstructs to 1");
    Require(engine.Eval(false, keys.left, 5) + engine.Eval(true, keys.right, 5) == 0, "non-point reconstructs to 0");

    auto seq0 = engine.EvalAllSequential(false, keys.left);
    auto par0 = engine.EvalAllParallel(false, keys.left, 4);
    auto seq1 = engine.EvalAllSequential(true, keys.right);
    auto par1 = engine.EvalAllParallel(true, keys.right, 4);
    Require(seq0 == par0, "party 0 sequential and parallel outputs match");
    Require(seq1 == par1, "party 1 sequential and parallel outputs match");

    constexpr size_t kBlockCount = 3;
    std::vector<uint64_t> payload(kDomainSize * kBlockCount, 0);
    for (size_t i = 0; i < kDomainSize; ++i) {
        payload[i * kBlockCount + 0] = 1000 + i;
        payload[i * kBlockCount + 1] = 2000 + i;
        payload[i * kBlockCount + 2] = 3000 + i;
    }
    auto left_share = engine.AggregateU64Blocks(false, keys.left, payload, kDomainSize, kBlockCount, 4);
    auto right_share = engine.AggregateU64Blocks(true, keys.right, payload, kDomainSize, kBlockCount, 4);
    auto reconstructed = engine.ReconstructU64Blocks(left_share, right_share);
    Require(reconstructed[0] == payload[kAlpha * kBlockCount + 0], "aggregate block 0 matches selected payload");
    Require(reconstructed[1] == payload[kAlpha * kBlockCount + 1], "aggregate block 1 matches selected payload");
    Require(reconstructed[2] == payload[kAlpha * kBlockCount + 2], "aggregate block 2 matches selected payload");

    PQGeneratedKeys c_keys{};
    Require(generate_query_key(kAlpha, kDomainSize, random.data(), random.size(), &c_keys) == 0, "C API generate succeeds");

    std::vector<uint64_t> c_left(kBlockCount, 0);
    std::vector<uint64_t> c_right(kBlockCount, 0);
    Require(
        aggregate_query_share(0, &c_keys.left, payload.data(), kDomainSize, kBlockCount, 4, c_left.data()) == 0,
        "C API left aggregate succeeds");
    Require(
        aggregate_query_share(1, &c_keys.right, payload.data(), kDomainSize, kBlockCount, 4, c_right.data()) == 0,
        "C API right aggregate succeeds");

    std::vector<uint64_t> c_reconstructed(kBlockCount, 0);
    Require(
        reconstruct_u64_blocks(c_left.data(), c_right.data(), kBlockCount, c_reconstructed.data()) == 0,
        "C API reconstruct succeeds");
    Require(c_reconstructed == reconstructed, "C API reconstruction matches C++ result");

    free_generated_query_key(&c_keys);

    std::puts("pq-dpf-core native tests passed");
    return 0;
}
