#pragma once

#include "flat_file_map.hpp"

struct flat_file_records_header {
    
} __attribute__((packed));

template<typename record_type>
struct flat_file_records {
    flat_file_map& file_map;

    inline uint64_t& pool_offset() {
        return file_map.mmap_cast<uint64_t>(0);
    }

};