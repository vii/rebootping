#pragma once

#include "cmake_variables.hpp"
#include "flat_mmap.hpp"
#include "now_unixtime.hpp"
#include "str.hpp"

struct flat_hash_header {
    uint64_t flat_hash_magic = 0x666c617468617368;
    uint64_t flat_hash_version = 202101210000;
    double flat_hash_git_unixtime = flat_git_unixtime;
    uint8_t flat_hash_git_sha_string_array[128] = flat_git_sha_string;
    double flat_hash_create_unixtime = now_unixtime();

    uint64_t flat_hash_entry_count = 0;
};

// Fast splittable pseudorandom number generators
// http://gee.cs.oswego.edu/dl/papers/oopsla14.pdf
inline uint64_t constexpr flat_hash_mix(uint64_t z) {
    z = (z ^ (z >> 33)) * 0xff51afd7ed558ccdULL;
    z = (z ^ (z >> 33)) * 0xc4ceb9fe1a85ec53ULL;
    return z ^ (z >> 33);
}

template <typename key_type> inline uint64_t flat_hash_function(key_type const &k) { return flat_hash_mix(k); }

template <uint64_t max_val> struct smallest_uint {
    using type = typename std::conditional < max_val < (1 << 8), uint8_t,
          typename std::conditional < max_val<(1 << 16), uint16_t, typename std::conditional<max_val<(1llu << 32), uint32_t, uint64_t>::type>::type>::type;
};
static_assert(std::is_integral<smallest_uint<1l << 31>::type>::value);

// sizeof(flat_hash_page) = sizeof(counter_type)*(markers_count+1)+(sizeof(key_type)+sizeof(value_type))*values_count
template <typename key_type, typename value_type, unsigned markers_count, unsigned values_count> struct flat_hash_page {
    using marker_type = typename smallest_uint<markers_count>::type;
    using counter_type = typename smallest_uint<values_count>::type;

    counter_type page_slots[markers_count];
    counter_type page_next_value;

    key_type page_keys[values_count];
    value_type page_values[values_count];

    template <typename key_compare_function> value_type *page_add_key(marker_type marker, key_type const &k, key_compare_function &&compare) {
        auto &slot = page_slots[marker];
        if (slot) {
            if (flat_hash_compare(compare, page_keys[slot - 1], k)) { return &page_values[slot - 1]; }
            return nullptr;
        }
        if (page_next_value >= values_count) { return nullptr; }
        slot = ++page_next_value;
        page_keys[slot - 1] = k;
        return &page_values[slot - 1];
    }

    template <typename key_to_marker> bool page_del_key(marker_type marker, key_type const &k, key_to_marker ktm) {
        if (!page_find_key(marker, k)) { return false; }
        auto &slot = page_slots[marker];
        auto last_slot = page_next_value--;
        auto last_marker = ktm(page_keys[last_slot - 1]);
        if (last_marker != marker) {
            page_slots[last_marker] = slot;
            page_keys[slot - 1] = page_keys[last_slot - 1];
            page_values[slot - 1] = page_values[last_slot - 1];
        }
        return true;
    }

    template <typename key_compare_function> value_type *page_find_key(marker_type marker, key_type const &k, key_compare_function &&compare) {
        auto const slot = page_slots[marker];
        if (!slot) { return nullptr; }
        if (!flat_hash_compare(compare, page_keys[slot - 1], k)) { return nullptr; }
        return &page_values[slot - 1];
    }
};

inline constexpr uint64_t ror(uint64_t val, unsigned amount) {
    amount &= 63;
    return (val >> amount) | (val << (64 - amount));
}
static_assert(ror(1, 1) == (1ull << 63), "ror 1");

struct flat_hash_function_class {
    template <typename... args_types> decltype(auto) operator()(args_types &&...args) const { return flat_hash_function(std::forward<args_types...>(args...)); }
};

struct flat_hash_compare_function_class {
    template <typename key_type, typename input_type> std::optional<key_type> compare_prepare_key_maybe(input_type &&i) const { return {(key_type)i}; }
    template <typename key_type, typename input_type> key_type compare_prepare_key(input_type &&i) const { return (key_type)i; }
};

template <typename comparer, typename lhs_type, typename rhs_type, typename... fallback_overload>
inline bool flat_hash_compare(comparer const &, lhs_type const &lhs, rhs_type const &rhs, [[maybe_unused]] fallback_overload &&...ignored) {
    return lhs == rhs;
}

template <typename key_type, typename comparer, typename input_type> inline decltype(auto) flat_hash_prepare_key_maybe(comparer const &c, input_type &&i) {
    return c.template compare_prepare_key_maybe<key_type>(i);
}

template <typename key_type, typename comparer, typename input_type> inline decltype(auto) flat_hash_prepare_key(comparer const &c, input_type &&i) {
    return c.template compare_prepare_key<key_type>(i);
}

template <typename key_type, typename value_type, typename hash_function = flat_hash_function_class,
          typename compare_function = flat_hash_compare_function_class, unsigned marker_bits = 8>
struct flat_hash : hash_function {
    flat_mmap hash_mmap;
    using hash_page_type = flat_hash_page<key_type, value_type, 1 << marker_bits, 1 << (marker_bits - 1)>;
    using marker_type = typename hash_page_type::marker_type;
    [[no_unique_address]] compare_function hash_compare_function;

    template <typename... arg_types>
    explicit flat_hash(std::string filename, flat_mmap_settings const &settings = flat_mmap_settings(),
                       compare_function &&passed_compare_function = compare_function(), arg_types &&...args)
        : hash_function(std::forward<arg_types>(args)...), hash_mmap(filename, settings), hash_compare_function(passed_compare_function) {
        if (!hash_mmap.mmap_allocated_len()) {
            hash_mmap.mmap_allocate_at_least(sizeof(flat_hash_header));
            hash_header() = flat_hash_header();
        } else {
            flat_hash_header highest_supported_version;
            if (highest_supported_version.flat_hash_magic != hash_header().flat_hash_magic) {
                throw std::runtime_error(str("flat_hash_magic does not match ", hash_header().flat_hash_magic));
            }
            if (hash_header().flat_hash_version > highest_supported_version.flat_hash_version) {
                throw std::runtime_error(str("flat_hash_version too new: ", hash_header().flat_hash_version, ">", highest_supported_version.flat_hash_version));
            }
        }
    }
    flat_hash_header &hash_header() { return hash_mmap.template mmap_cast<flat_hash_header>(0); }

    static inline constexpr uint64_t hash_level_offset(unsigned level) { return ((1 << level) - 1) * sizeof(hash_page_type) + sizeof(flat_hash_header); }
    static_assert(hash_level_offset(0) - sizeof(flat_hash_header) == 0, "first level starts at 0");
    static_assert(hash_level_offset(1) - sizeof(flat_hash_header) == 1 * sizeof(hash_page_type), "second level starts at 1");
    static_assert(hash_level_offset(2) - sizeof(flat_hash_header) == 3 * sizeof(hash_page_type), "second level starts at 3");
    static_assert(hash_level_offset(3) - sizeof(flat_hash_header) == 7 * sizeof(hash_page_type), "third level starts at 7");

    hash_page_type &hash_page_for_level(unsigned level, uint64_t rotated_hash) const {
        uint64_t page_jump = rotated_hash & ((1 << level) - 1);
        assert(hash_level_offset(level + 1) > hash_level_offset(level) + page_jump * sizeof(hash_page_type));
        return hash_mmap.mmap_cast<hash_page_type>(hash_level_offset(level) + page_jump * sizeof(hash_page_type));
    }

    template <typename input_key> value_type *hash_find_key(input_key &&ik) const {
        auto mk = flat_hash_prepare_key_maybe<key_type>(hash_compare_function, ik);
        if (!mk) { return nullptr; }
        auto k = *mk;
        auto rotated_hash = (*this)(k);
        for (unsigned level = 0; hash_mmap.mmap_allocated_len() >= hash_level_offset(level + 1); ++level) {
            assert(hash_level_offset(level + 1) >= hash_level_offset(level));
            auto &page = hash_page_for_level(level, rotated_hash);
            rotated_hash = ror(rotated_hash, level);
            if (auto v = page.page_find_key((marker_type)(rotated_hash & ((1 << marker_bits) - 1)), k, hash_compare_function)) { return v; }
        }
        return nullptr;
    }

    template <typename input_key> value_type &hash_add_key(input_key &&ik) {
        auto k = flat_hash_prepare_key<key_type>(hash_compare_function, ik);

        auto rotated_hash = (*this)(k);
        unsigned level;
        for (level = 0; hash_mmap.mmap_allocated_len() >= hash_level_offset(level + 1); ++level) {
            auto &page = hash_page_for_level(level, rotated_hash);

            rotated_hash = ror(rotated_hash, level);
            if (auto v = page.page_add_key(rotated_hash & ((1 << marker_bits) - 1), k, hash_compare_function)) { return *v; }
        }
        hash_mmap.mmap_sparsely_allocate_at_least(hash_level_offset(level + 1));
        auto &page = hash_page_for_level(level, rotated_hash);
        rotated_hash = ror(rotated_hash, level);
        ++hash_header().flat_hash_entry_count;
        return *page.page_add_key(rotated_hash & ((1 << marker_bits) - 1), k, hash_compare_function);
    }

    template <typename input_key> bool hash_del_key(input_key &&ik) {
        auto mk = flat_hash_maybe_prepare_key<key_type>(hash_compare_function, ik);
        if (!mk) { return false; }
        auto k = *mk;
        auto rotated_hash = (*this)(k);
        for (unsigned level = 0; hash_mmap.mmap_allocated_len() >= hash_level_offset(level + 1); ++level) {
            auto &page = hash_page_for_level(level, rotated_hash);
            rotated_hash = ror(rotated_hash, level);
            if (page.page_del_key((marker_type)(rotated_hash & ((1 << marker_bits) - 1)), k,
                                  [level, this](key_type const &nk) { return ror((*this)(nk), (level * (level + 1)) / 2) & ((1 << marker_bits) - 1); })) {
                --hash_header().flat_hash_entry_count;
                return true;
            }
        }
        return false;
    }

    template <typename Walker> void hash_walk(Walker &&walker) {
        for (uint64_t offset = hash_level_offset(0); offset + sizeof(hash_page_type) <= hash_mmap.mmap_allocated_len(); offset += sizeof(hash_page_type)) {
            auto &page = hash_mmap.mmap_cast<hash_page_type>(offset);
            for (typename hash_page_type::counter_type c = 0; c < page.page_next_value; ++c) { walker(page.page_keys[c], page.page_values[c]); }
        }
    }
};

namespace {
inline void flat_hash_test_instantiate(flat_hash<uint64_t, uint64_t> &f) {
    f.hash_find_key(0);
    f.hash_add_key(0);
}
} // namespace