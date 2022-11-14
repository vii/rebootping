#pragma once

#include <array>
#include <cstdint>
#include <unordered_map>

template <typename key_type, uint64_t mfu, uint64_t mru> struct flat_mfu_mru {
    std::array<key_type, mfu> flat_mfu_keys = {};
    std::array<uint64_t, mfu> flat_mfu_counts = {};
    std::array<key_type, mru> flat_mru_keys = {};
    std::array<uint64_t, mru> flat_mru_counts = {};
    uint64_t mru_pointer = 0;

    void notice_key(const key_type &key) {
        uint64_t emptiest_slot = 0;
        uint64_t emptiest_count = flat_mfu_counts[emptiest_slot];
        for (uint64_t n = 0; mfu > n; ++n) {
            if (flat_mfu_keys[n] == key) {
                ++flat_mfu_counts[n];
                return;
            }
            if (flat_mfu_counts[n] < emptiest_count) {
                emptiest_slot = n;
                emptiest_count = flat_mfu_counts[n];
            }
        }
        if (!emptiest_count) {
            flat_mfu_keys[emptiest_slot] = key;
            flat_mfu_counts[emptiest_slot] = 1;
            return;
        }

        if (!mru) { return; }

        if (flat_mru_keys[mru_pointer] == key) {
            ++flat_mru_counts[mru_pointer];
        } else {
            uint64_t count = 1;
            for (uint64_t n = 0; mru > n; ++n) {
                if (flat_mru_keys[n] == key) {
                    count += flat_mru_counts[n];
                    flat_mru_keys[n] = key_type();
                    flat_mru_counts[n] = 0;
                }
            }
            mru_pointer = (mru_pointer + 1) % mru;
            if (flat_mru_counts[mru_pointer] > emptiest_count) {
                flat_mfu_keys[emptiest_slot] = flat_mru_keys[mru_pointer];
                flat_mfu_counts[emptiest_slot] = flat_mru_counts[mru_pointer];
            }
            flat_mru_keys[mru_pointer] = key;
            flat_mru_counts[mru_pointer] = count;
        }
    }

    std::unordered_map<key_type, uint64_t> known_keys_and_counts() const {
        std::unordered_map<key_type, uint64_t> ret;
        for (uint64_t n = 0; mfu > n; ++n) {
            if (flat_mfu_counts[n]) { ret[flat_mfu_keys[n]] = flat_mfu_counts[n]; }
        }
        for (uint64_t n = 0; mru > n; ++n) {
            if (flat_mru_counts[n]) { ret[flat_mru_keys[n]] = flat_mru_counts[n]; }
        }
        return ret;
    }
};
