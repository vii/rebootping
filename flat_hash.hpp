#pragma once

#include "flat_mmap.hpp"

// Fast splittable pseudorandom number generators
// http://gee.cs.oswego.edu/dl/papers/oopsla14.pdf
inline uint64_t flat_hash_mix(uint64_t z) {
    z = (z ^ (z >> 33)) * 0xff51afd7ed558ccdULL;
    z = (z ^ (z >> 33)) * 0xc4ceb9fe1a85ec53ULL;
    return z ^ (z >> 33);
}

template<typename key_type>
struct flat_hash_type {
    using hash_type = uint64_t;
};
template<>
struct flat_hash_type<uint32_t> {
    using hash_type = uint32_t;
};

template<typename key_type> inline
typename flat_hash_type<key_type>::hash_type flat_hash_value(key_type const&k){
    return static_cast<typename flat_hash_type<key_type>::hash_type>(flat_hash_mix(k));
}

template<uint64_t max_val>
struct smallest_uint {
    using type = typename std::conditional<max_val < (1<<8),
          uint8_t,
          typename std::conditional<max_val < (1<<16),
                uint16_t, typename std::conditional<max_val < (1llu<<32), uint32_t, uint64_t  >::type >::type >::type;
};
static_assert(std::is_integral<smallest_uint<1l<<31>::type>::value);

template<typename key_type, typename value_type, unsigned markers_count, unsigned values_count>
struct flat_hash_page {
    using hash_type = typename flat_hash_type<key_type>::hash_type;
    using marker_type = typename smallest_uint<markers_count>::type;
    using counter_type = typename smallest_uint<values_count>::type;

    counter_type page_slots[markers_count];

    counter_type page_next_value;

    key_type page_keys[values_count];
    value_type page_values[values_count];

    value_type* page_add_key(marker_type marker, key_type const& k) {
        auto& slot = page_slots[marker];
        if(slot) {
            if (page_keys[slot-1] == k) {
                return &page_values[slot-1];
            }
            return nullptr;
        }
        if (page_next_value >= values_count) {
            return nullptr;
        }
        slot = ++page_next_value;
        page_keys[slot-1] = k;
        return &page_values[slot-1];
    }

    template<typename key_to_marker>
    void page_del_key(marker_type marker, key_to_marker ktm) {
        auto& slot = page_slots[marker];
        if (!slot) {
            return;
        }
        auto last_slot = page_next_value--;
        auto last_marker = ktm(page_keys[last_slot-1]);
        if (last_marker != marker) {
            page_slots[last_marker] = slot;
            page_keys[slot-1] = page_keys[last_slot-1];
            page_values[slot-1] = page_values[last_slot-1];
        }
    }

    value_type* page_find_key(marker_type marker, key_type const& k) {
        auto const slot = page_slots[marker];
        if (!slot) {
            return nullptr;
        }
        if (page_keys[slot-1] != k) {
            return nullptr;
        }
        return &page_values[slot-1];
    }

};

inline constexpr
uint64_t ror(uint64_t val, unsigned amount) {
    amount &= 63;
    return (val >> amount) | (val<< (64-amount));
}
static_assert(ror(1,1)==(1ull<<63), "ror 1");

template<typename key_type, typename value_type, unsigned marker_bits=8>
struct flat_hash {
    flat_mmap hash_mmap;
    using hash_type = typename flat_hash_type<key_type>::hash_type;
    using hash_page_type = flat_hash_page<key_type, value_type, 1<<marker_bits, 1<<(marker_bits-1)>;
    using marker_type = typename hash_page_type::marker_type;

    template<typename... arg_types>
    flat_hash(arg_types&& ...args) : hash_mmap(std::forward<arg_types...>(args...)) {

    }

    static inline constexpr
    uint64_t hash_level_offset(unsigned level){
        return ((1<<level)-1)*sizeof(hash_page_type);
    }
    static_assert(hash_level_offset(0) == 0, "first level starts at 0");
    static_assert(hash_level_offset(1) == sizeof(hash_page_type), "second level starts at 1");
    static_assert(hash_level_offset(2) == 3*sizeof(hash_page_type), "second level starts at 3");
    static_assert(hash_level_offset(3) == 7*sizeof(hash_page_type), "third level starts at 7");

    hash_page_type& hash_page_for_level(unsigned level, uint64_t rotated_hash) {
        return hash_mmap.mmap_cast<hash_page_type>(
                hash_level_offset(level)+(rotated_hash&((1<<level)-1))*sizeof(hash_page_type)
        );
    }

    value_type* hash_find_key(key_type const&k) {
        auto rotated_hash = flat_hash_value(k);
        for(unsigned level=0;hash_mmap.mmap_allocated_len()>=hash_level_offset(level+1);++level){
            auto& page = hash_page_for_level(level, rotated_hash);
            rotated_hash = ror(rotated_hash, level);
            if (auto v = page.page_find_key((marker_type)(rotated_hash&((1<<marker_bits)-1)), k)) {
                return v;
            }
        }
        return nullptr;
    }
    value_type* hash_add_key(key_type const&k) {
        auto rotated_hash = flat_hash_value(k);
        unsigned level;
        for(level=0;hash_mmap.mmap_allocated_len()>=hash_level_offset(level+1);++level){
            auto& page = hash_page_for_level(level, rotated_hash);

            rotated_hash = ror(rotated_hash, level);
            if (auto v = page.page_add_key(rotated_hash&((1<<marker_bits)-1), k)) {
                return v;
            }
        }
        hash_mmap.mmap_allocate_at_least(hash_level_offset(level+1));
        auto& page = hash_page_for_level(level, rotated_hash);
        rotated_hash = ror(rotated_hash, level);
        return page.page_add_key(rotated_hash&((1<<marker_bits)-1), k);
    }

};


namespace {
    inline void flat_hash_test_instantiate(flat_hash<uint64_t, uint64_t>&f) {
        f.hash_find_key(0);
        f.hash_add_key(0);
    }
}