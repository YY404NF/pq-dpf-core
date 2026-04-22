// SPDX-License-Identifier: Apache-2.0
//
// This file adapts DPF CPU-path logic from myl7/fss:
// https://github.com/myl7/fss
#pragma once

#include <array>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace pq::dpf_core {

struct Block128 {
    uint32_t x;
    uint32_t y;
    uint32_t z;
    uint32_t w;
};

struct CorrectionWord {
    Block128 s;
    bool tr;
};

struct KeyShare {
    Block128 seed;
    std::vector<CorrectionWord> correction_words;
    uint32_t in_bits;
    uint64_t domain_size;
};

struct GeneratedKeyPair {
    KeyShare left;
    KeyShare right;
};

inline bool operator==(const Block128 &lhs, const Block128 &rhs) {
    return lhs.x == rhs.x && lhs.y == rhs.y && lhs.z == rhs.z && lhs.w == rhs.w;
}

inline Block128 Xor(const Block128 &lhs, const Block128 &rhs) {
    return {lhs.x ^ rhs.x, lhs.y ^ rhs.y, lhs.z ^ rhs.z, lhs.w ^ rhs.w};
}

inline Block128 SetLsb(Block128 value, bool bit) {
    if (bit) {
        value.w |= 1U;
    } else {
        value.w &= ~1U;
    }
    return value;
}

inline bool GetLsb(const Block128 &value) {
    return (value.w & 1U) != 0;
}

inline uint64_t ToUint64(const Block128 &value) {
    return static_cast<uint64_t>(value.x) | (static_cast<uint64_t>(value.y) << 32U);
}

inline Block128 FromUint64(uint64_t value) {
    return {
        static_cast<uint32_t>(value & 0xFFFFFFFFULL),
        static_cast<uint32_t>((value >> 32U) & 0xFFFFFFFFULL),
        0U,
        0U,
    };
}

inline bool IsPowerOfTwo(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

inline uint32_t ResolveInBits(uint64_t domain_size) {
    uint32_t bits = 0;
    while ((1ULL << bits) < domain_size) {
        ++bits;
    }
    return bits;
}

inline uint64_t AddMod64(uint64_t lhs, uint64_t rhs) {
    return lhs + rhs;
}

inline uint64_t NegMod64(uint64_t value) {
    return static_cast<uint64_t>(0) - value;
}

inline uint64_t MulMod64(uint64_t lhs, uint64_t rhs) {
    return lhs * rhs;
}

class Aes128MmoSoft {
public:
    explicit Aes128MmoSoft(std::array<std::array<uint8_t, 16>, 2> keys) {
        InitSbox();
        InitTe0();
        for (size_t i = 0; i < keys.size(); ++i) {
            KeyExpansion(round_keys_[i].data(), keys[i].data());
        }
    }

    std::array<Block128, 2> Gen(const Block128 &seed) const {
        std::array<Block128, 2> out{};
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] = seed;
            Encrypt(reinterpret_cast<uint8_t *>(&out[i]), round_keys_[i].data());
            out[i] = Xor(out[i], seed);
        }
        return out;
    }

private:
    static constexpr int kNb = 4;
    static constexpr int kNk = 4;
    static constexpr int kNr = 10;
    static constexpr size_t kRoundKeySize = kNb * (kNr + 1) * 4;

    std::array<uint8_t, 256> sbox_{};
    std::array<uint32_t, 256> te0_{};
    std::array<std::array<uint8_t, kRoundKeySize>, 2> round_keys_{};

    void InitSbox() {
        sbox_ = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
            0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
            0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
            0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
            0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
            0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
            0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
            0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
            0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
            0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
            0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
            0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
            0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
            0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
            0xb0, 0x54, 0xbb, 0x16,
        };
    }

    static uint8_t Rcon(int idx) {
        constexpr std::array<uint8_t, 11> table = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        };
        return table[static_cast<size_t>(idx)];
    }

    static uint32_t RotWord8(uint32_t x) {
        return (x << 24U) | (x >> 8U);
    }

    static uint32_t RotWord16(uint32_t x) {
        return (x << 16U) | (x >> 16U);
    }

    static uint32_t RotWord24(uint32_t x) {
        return (x << 8U) | (x >> 24U);
    }

    static uint8_t Xt(uint8_t value) {
        return static_cast<uint8_t>((value << 1U) ^ (((value >> 7U) & 1U) * 0x1bU));
    }

    void InitTe0() {
        for (size_t i = 0; i < te0_.size(); ++i) {
            const auto s = sbox_[i];
            const auto x2 = Xt(s);
            const auto x3 = static_cast<uint8_t>(s ^ x2);
            te0_[i] = (static_cast<uint32_t>(x2) << 24U) | (static_cast<uint32_t>(s) << 16U) |
                (static_cast<uint32_t>(s) << 8U) | static_cast<uint32_t>(x3);
        }
    }

    void KeyExpansion(uint8_t *round_key, const uint8_t *key) const {
        for (int i = 0; i < kNk; ++i) {
            round_key[i * 4 + 0] = key[i * 4 + 0];
            round_key[i * 4 + 1] = key[i * 4 + 1];
            round_key[i * 4 + 2] = key[i * 4 + 2];
            round_key[i * 4 + 3] = key[i * 4 + 3];
        }
        for (int i = kNk; i < kNb * (kNr + 1); ++i) {
            uint8_t temp[4];
            int k = (i - 1) * 4;
            temp[0] = round_key[k + 0];
            temp[1] = round_key[k + 1];
            temp[2] = round_key[k + 2];
            temp[3] = round_key[k + 3];
            if (i % kNk == 0) {
                uint8_t first = temp[0];
                temp[0] = sbox_[temp[1]];
                temp[1] = sbox_[temp[2]];
                temp[2] = sbox_[temp[3]];
                temp[3] = sbox_[first];
                temp[0] ^= Rcon(i / kNk);
            }
            const int dst = i * 4;
            const int src = (i - kNk) * 4;
            round_key[dst + 0] = round_key[src + 0] ^ temp[0];
            round_key[dst + 1] = round_key[src + 1] ^ temp[1];
            round_key[dst + 2] = round_key[src + 2] ^ temp[2];
            round_key[dst + 3] = round_key[src + 3] ^ temp[3];
        }
    }

    static uint32_t LoadBE32(const uint8_t *p) {
        return (static_cast<uint32_t>(p[0]) << 24U) | (static_cast<uint32_t>(p[1]) << 16U) |
            (static_cast<uint32_t>(p[2]) << 8U) | static_cast<uint32_t>(p[3]);
    }

    static void StoreBE32(uint8_t *p, uint32_t value) {
        p[0] = static_cast<uint8_t>(value >> 24U);
        p[1] = static_cast<uint8_t>(value >> 16U);
        p[2] = static_cast<uint8_t>(value >> 8U);
        p[3] = static_cast<uint8_t>(value);
    }

    void Encrypt(uint8_t *buf, const uint8_t *round_key) const {
        uint32_t s0 = LoadBE32(buf) ^ LoadBE32(round_key);
        uint32_t s1 = LoadBE32(buf + 4) ^ LoadBE32(round_key + 4);
        uint32_t s2 = LoadBE32(buf + 8) ^ LoadBE32(round_key + 8);
        uint32_t s3 = LoadBE32(buf + 12) ^ LoadBE32(round_key + 12);

        for (int round = 1; round <= 9; ++round) {
            const auto *rk = round_key + round * 16;
            const uint32_t rk0 = LoadBE32(rk);
            const uint32_t rk1 = LoadBE32(rk + 4);
            const uint32_t rk2 = LoadBE32(rk + 8);
            const uint32_t rk3 = LoadBE32(rk + 12);

            const uint32_t t0 = te0_[s0 >> 24U] ^ RotWord8(te0_[(s1 >> 16U) & 0xffU]) ^
                RotWord16(te0_[(s2 >> 8U) & 0xffU]) ^ RotWord24(te0_[s3 & 0xffU]) ^ rk0;
            const uint32_t t1 = te0_[s1 >> 24U] ^ RotWord8(te0_[(s2 >> 16U) & 0xffU]) ^
                RotWord16(te0_[(s3 >> 8U) & 0xffU]) ^ RotWord24(te0_[s0 & 0xffU]) ^ rk1;
            const uint32_t t2 = te0_[s2 >> 24U] ^ RotWord8(te0_[(s3 >> 16U) & 0xffU]) ^
                RotWord16(te0_[(s0 >> 8U) & 0xffU]) ^ RotWord24(te0_[s1 & 0xffU]) ^ rk2;
            const uint32_t t3 = te0_[s3 >> 24U] ^ RotWord8(te0_[(s0 >> 16U) & 0xffU]) ^
                RotWord16(te0_[(s1 >> 8U) & 0xffU]) ^ RotWord24(te0_[s2 & 0xffU]) ^ rk3;

            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
        }

        const auto *rk = round_key + 160;
        const uint32_t rk0 = LoadBE32(rk);
        const uint32_t rk1 = LoadBE32(rk + 4);
        const uint32_t rk2 = LoadBE32(rk + 8);
        const uint32_t rk3 = LoadBE32(rk + 12);

        const uint32_t o0 = (static_cast<uint32_t>(sbox_[s0 >> 24U]) << 24U) |
            (static_cast<uint32_t>(sbox_[(s1 >> 16U) & 0xffU]) << 16U) |
            (static_cast<uint32_t>(sbox_[(s2 >> 8U) & 0xffU]) << 8U) |
            static_cast<uint32_t>(sbox_[s3 & 0xffU]);
        const uint32_t o1 = (static_cast<uint32_t>(sbox_[s1 >> 24U]) << 24U) |
            (static_cast<uint32_t>(sbox_[(s2 >> 16U) & 0xffU]) << 16U) |
            (static_cast<uint32_t>(sbox_[(s3 >> 8U) & 0xffU]) << 8U) |
            static_cast<uint32_t>(sbox_[s0 & 0xffU]);
        const uint32_t o2 = (static_cast<uint32_t>(sbox_[s2 >> 24U]) << 24U) |
            (static_cast<uint32_t>(sbox_[(s3 >> 16U) & 0xffU]) << 16U) |
            (static_cast<uint32_t>(sbox_[(s0 >> 8U) & 0xffU]) << 8U) |
            static_cast<uint32_t>(sbox_[s1 & 0xffU]);
        const uint32_t o3 = (static_cast<uint32_t>(sbox_[s3 >> 24U]) << 24U) |
            (static_cast<uint32_t>(sbox_[(s0 >> 16U) & 0xffU]) << 16U) |
            (static_cast<uint32_t>(sbox_[(s1 >> 8U) & 0xffU]) << 8U) |
            static_cast<uint32_t>(sbox_[s2 & 0xffU]);

        StoreBE32(buf, o0 ^ rk0);
        StoreBE32(buf + 4, o1 ^ rk1);
        StoreBE32(buf + 8, o2 ^ rk2);
        StoreBE32(buf + 12, o3 ^ rk3);
    }
};

class DpfEngine {
public:
    DpfEngine()
        : prg_({std::array<uint8_t, 16>{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x21,
                      0x32, 0x43, 0x54, 0x65, 0x76, 0x87},
              std::array<uint8_t, 16>{0x87, 0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0xfe, 0xdc,
                  0xba, 0x98, 0x76, 0x54, 0x32, 0x10}}) {}

    GeneratedKeyPair GenerateKey(
        uint64_t alpha, uint64_t domain_size, std::span<const uint8_t> random_seed_bytes, uint64_t beta = 1) const {
        if (!IsPowerOfTwo(domain_size)) {
            throw std::invalid_argument("domain_size must be a power of two");
        }
        if (alpha >= domain_size) {
            throw std::invalid_argument("index is out of domain");
        }
        const auto in_bits = ResolveInBits(domain_size);
        auto seeds = DeriveSeeds(random_seed_bytes);
        auto cws = GenerateCorrectionWords(seeds, in_bits, alpha, beta);

        KeyShare left{seeds[0], cws, in_bits, domain_size};
        KeyShare right{seeds[1], cws, in_bits, domain_size};
        return {left, right};
    }

    uint64_t Eval(bool party, const KeyShare &key, uint64_t x) const {
        return EvalInternal(party, key.seed, key.correction_words, key.in_bits, x);
    }

    std::vector<uint64_t> EvalAllSequential(bool party, const KeyShare &key) const {
        std::vector<uint64_t> outputs(static_cast<size_t>(key.domain_size), 0);
        for (uint64_t x = 0; x < key.domain_size; ++x) {
            outputs[static_cast<size_t>(x)] = Eval(party, key, x);
        }
        return outputs;
    }

    std::vector<uint64_t> EvalAllParallel(bool party, const KeyShare &key, uint32_t worker_count) const {
        const size_t domain_size = static_cast<size_t>(key.domain_size);
        std::vector<uint64_t> outputs(domain_size, 0);
        if (domain_size == 0) {
            return outputs;
        }
        if (worker_count <= 1 || domain_size <= 1) {
            return EvalAllSequential(party, key);
        }

        const auto split_depth = ResolveSplitDepth(worker_count);
        std::vector<TaskState> tasks;
        tasks.reserve(static_cast<size_t>(1U << split_depth));

        Block128 state = SetLsb(key.seed, party);
        SplitTasks(state, key.correction_words, key.in_bits, 0, 0, domain_size, split_depth, tasks);
        if (tasks.empty()) {
            tasks.push_back({state, 0, domain_size, 0});
        }

        const size_t thread_count = std::min(tasks.size(), static_cast<size_t>(worker_count));
        std::atomic<size_t> next{0};
        std::vector<std::thread> threads;
        threads.reserve(thread_count);
        for (size_t i = 0; i < thread_count; ++i) {
            threads.emplace_back([&, party]() {
                while (true) {
                    const auto idx = next.fetch_add(1);
                    if (idx >= tasks.size()) {
                        break;
                    }
                    const auto &task = tasks[idx];
                    FillRange(party, task.state, key.correction_words, key.in_bits, outputs, task.left, task.right, task.depth);
                }
            });
        }
        for (auto &thread : threads) {
            thread.join();
        }
        return outputs;
    }

    std::vector<uint64_t> AggregateU64Blocks(
        bool party,
        const KeyShare &key,
        std::span<const uint64_t> payload_blocks,
        size_t record_count,
        size_t block_count,
        uint32_t worker_count) const {
        if (payload_blocks.size() < record_count * block_count) {
            throw std::invalid_argument("payload block buffer is too small");
        }
        auto weights = EvalAllParallel(party, key, worker_count);
        std::vector<uint64_t> result(block_count, 0);
        for (size_t row = 0; row < record_count; ++row) {
            const auto weight = weights[row];
            if (weight == 0) {
                continue;
            }
            const size_t base = row * block_count;
            for (size_t col = 0; col < block_count; ++col) {
                result[col] = AddMod64(result[col], MulMod64(weight, payload_blocks[base + col]));
            }
        }
        return result;
    }

    std::vector<uint64_t> ReconstructU64Blocks(
        std::span<const uint64_t> left_blocks, std::span<const uint64_t> right_blocks) const {
        if (left_blocks.size() != right_blocks.size()) {
            throw std::invalid_argument("reconstruction buffers must have equal length");
        }
        std::vector<uint64_t> output(left_blocks.size(), 0);
        for (size_t i = 0; i < left_blocks.size(); ++i) {
            output[i] = AddMod64(left_blocks[i], right_blocks[i]);
        }
        return output;
    }

private:
    struct TaskState {
        Block128 state;
        size_t left;
        size_t right;
        uint32_t depth;
    };

    Aes128MmoSoft prg_;

    static uint64_t SplitMix64(uint64_t &state) {
        state += 0x9e3779b97f4a7c15ULL;
        uint64_t z = state;
        z = (z ^ (z >> 30U)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27U)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31U);
    }

    static std::array<Block128, 2> DeriveSeeds(std::span<const uint8_t> bytes) {
        uint64_t s0 = 0x243f6a8885a308d3ULL;
        uint64_t s1 = 0x13198a2e03707344ULL;
        for (const auto byte : bytes) {
            s0 ^= static_cast<uint64_t>(byte) + 0x9e3779b97f4a7c15ULL + (s0 << 6U) + (s0 >> 2U);
            s1 ^= static_cast<uint64_t>(byte) + 0xc2b2ae3d27d4eb4fULL + (s1 << 6U) + (s1 >> 2U);
        }

        std::array<Block128, 2> seeds{};
        for (size_t i = 0; i < seeds.size(); ++i) {
            uint64_t a = SplitMix64(i == 0 ? s0 : s1);
            uint64_t b = SplitMix64(i == 0 ? s0 : s1);
            seeds[i] = {
                static_cast<uint32_t>(a & 0xFFFFFFFFULL),
                static_cast<uint32_t>((a >> 32U) & 0xFFFFFFFFULL),
                static_cast<uint32_t>(b & 0xFFFFFFFFULL),
                static_cast<uint32_t>((b >> 32U) & 0xFFFFFFFFULL),
            };
            seeds[i] = SetLsb(seeds[i], false);
        }
        return seeds;
    }

    std::vector<CorrectionWord> GenerateCorrectionWords(
        std::array<Block128, 2> seeds, uint32_t in_bits, uint64_t alpha, uint64_t beta) const {
        Block128 s0 = SetLsb(seeds[0], false);
        Block128 s1 = SetLsb(seeds[1], false);
        bool t0 = false;
        bool t1 = true;

        std::vector<CorrectionWord> cws(static_cast<size_t>(in_bits) + 1U);
        for (uint32_t i = 0; i < in_bits; ++i) {
            auto out0 = prg_.Gen(s0);
            auto out1 = prg_.Gen(s1);

            bool t0l = GetLsb(out0[0]);
            bool t0r = GetLsb(out0[1]);
            bool t1l = GetLsb(out1[0]);
            bool t1r = GetLsb(out1[1]);

            auto s0l = SetLsb(out0[0], false);
            auto s0r = SetLsb(out0[1], false);
            auto s1l = SetLsb(out1[0], false);
            auto s1r = SetLsb(out1[1], false);

            const bool a_bit = ((alpha >> (in_bits - 1U - i)) & 1ULL) != 0;
            Block128 s_cw = !a_bit ? Xor(s0r, s1r) : Xor(s0l, s1l);
            const bool tl_cw = static_cast<bool>(t0l ^ t1l ^ a_bit ^ 1U);
            const bool tr_cw = static_cast<bool>(t0r ^ t1r ^ a_bit);

            if (!a_bit) {
                s0 = s0l;
                if (t0) {
                    s0 = Xor(s0, s_cw);
                }
                s1 = s1l;
                if (t1) {
                    s1 = Xor(s1, s_cw);
                }
                t0 = t0 ? static_cast<bool>(t0l ^ tl_cw) : t0l;
                t1 = t1 ? static_cast<bool>(t1l ^ tl_cw) : t1l;
            } else {
                s0 = s0r;
                if (t0) {
                    s0 = Xor(s0, s_cw);
                }
                s1 = s1r;
                if (t1) {
                    s1 = Xor(s1, s_cw);
                }
                t0 = t0 ? static_cast<bool>(t0r ^ tr_cw) : t0r;
                t1 = t1 ? static_cast<bool>(t1r ^ tr_cw) : t1r;
            }

            cws[i] = {SetLsb(s_cw, tl_cw), tr_cw};
        }

        uint64_t v = AddMod64(beta, AddMod64(NegMod64(ToUint64(s0)), ToUint64(s1)));
        if (t1) {
            v = NegMod64(v);
        }
        cws[static_cast<size_t>(in_bits)] = {FromUint64(v), false};
        return cws;
    }

    uint64_t EvalInternal(
        bool party, Block128 seed, const std::vector<CorrectionWord> &cws, uint32_t in_bits, uint64_t x) const {
        Block128 s = SetLsb(seed, false);
        bool t = party;

        for (uint32_t i = 0; i < in_bits; ++i) {
            auto cw = cws[i];
            Block128 s_cw = cw.s;
            const bool tl_cw = GetLsb(s_cw);
            s_cw = SetLsb(s_cw, false);
            const bool tr_cw = cw.tr;

            auto out = prg_.Gen(s);
            Block128 sl = SetLsb(out[0], false);
            Block128 sr = SetLsb(out[1], false);
            bool tl = GetLsb(out[0]);
            bool tr = GetLsb(out[1]);

            if (t) {
                sl = Xor(sl, s_cw);
                sr = Xor(sr, s_cw);
                tl = static_cast<bool>(tl ^ tl_cw);
                tr = static_cast<bool>(tr ^ tr_cw);
            }

            const bool x_bit = ((x >> (in_bits - 1U - i)) & 1ULL) != 0;
            if (!x_bit) {
                s = sl;
                t = tl;
            } else {
                s = sr;
                t = tr;
            }
        }

        uint64_t y = ToUint64(s);
        const auto v = ToUint64(cws[static_cast<size_t>(in_bits)].s);
        if (t) {
            y = AddMod64(y, v);
        }
        if (party) {
            y = NegMod64(y);
        }
        return y;
    }

    static uint32_t ResolveSplitDepth(uint32_t worker_count) {
        uint32_t depth = 0;
        uint32_t branches = 1;
        while (branches < worker_count) {
            branches <<= 1U;
            ++depth;
        }
        return depth;
    }

    void SplitTasks(
        Block128 state,
        const std::vector<CorrectionWord> &cws,
        uint32_t in_bits,
        uint32_t depth,
        size_t left,
        size_t right,
        uint32_t split_depth,
        std::vector<TaskState> &tasks) const {
        if (depth == in_bits || depth == split_depth) {
            tasks.push_back({state, left, right, depth});
            return;
        }

        auto next = ExpandNode(state, cws[depth]);
        const auto mid = left + (right - left) / 2U;
        SplitTasks(next.first, cws, in_bits, depth + 1U, left, mid, split_depth, tasks);
        SplitTasks(next.second, cws, in_bits, depth + 1U, mid, right, split_depth, tasks);
    }

    void FillRange(
        bool party,
        Block128 state,
        const std::vector<CorrectionWord> &cws,
        uint32_t in_bits,
        std::vector<uint64_t> &outputs,
        size_t left,
        size_t right,
        uint32_t depth) const {
        const bool t = GetLsb(state);
        const Block128 s = SetLsb(state, false);

        if (depth == in_bits) {
            uint64_t y = ToUint64(s);
            const auto v = ToUint64(cws[static_cast<size_t>(in_bits)].s);
            if (t) {
                y = AddMod64(y, v);
            }
            if (party) {
                y = NegMod64(y);
            }
            outputs[left] = y;
            return;
        }

        auto next = ExpandNode(state, cws[depth]);
        const auto mid = left + (right - left) / 2U;
        FillRange(party, next.first, cws, in_bits, outputs, left, mid, depth + 1U);
        FillRange(party, next.second, cws, in_bits, outputs, mid, right, depth + 1U);
    }

    std::pair<Block128, Block128> ExpandNode(Block128 state, const CorrectionWord &cw) const {
        const bool t = GetLsb(state);
        const Block128 s = SetLsb(state, false);
        auto out = prg_.Gen(s);
        Block128 sl = SetLsb(out[0], false);
        Block128 sr = SetLsb(out[1], false);
        bool tl = GetLsb(out[0]);
        bool tr = GetLsb(out[1]);

        Block128 s_cw = cw.s;
        const bool tl_cw = GetLsb(s_cw);
        s_cw = SetLsb(s_cw, false);
        const bool tr_cw = cw.tr;

        if (t) {
            sl = Xor(sl, s_cw);
            sr = Xor(sr, s_cw);
            tl = static_cast<bool>(tl ^ tl_cw);
            tr = static_cast<bool>(tr ^ tr_cw);
        }

        return {SetLsb(sl, tl), SetLsb(sr, tr)};
    }
};

}  // namespace pq::dpf_core
