#pragma once

#include "flat_macro.hpp"
#include "flat_mmap.hpp"

struct flat_index_bytes {
    uint64_t index_prev;
    uint64_t index_next;
    uint64_t index_pointer;
} __attribute__((packed));


template<typename hash_func_type, typename index_to_ref_type>
struct flat_index {
    index_to_ref_type index_to_ref;
    flat_hash<uint64_t, flat_index_bytes, > index_mmap;

    flat_index(hash_type &&hash_func, index_to_ref_type &&ref_func, std::string_view hash_file, std::string_view index_file, flat_mmap_settings const &settings)
        : index_hash_func{hash_func},
          index_to_ref{ref_func},
          index_mmap(hash_file, settings) {}
};