#pragma once

#include "flat_file_string.hpp"

#include <unordered_map>

template<typename offset_type, typename length_type>
struct flat_file_string_pool {
    using pool_string_type = flat_file_string<offset_type, length_type>;
    std::unordered_map<std::string, pool_string_type> pool_cache;
    flat_mmap &file_map;

    inline offset_type &pool_offset() {
        return file_map.mmap_cast<offset_type>(0);
    }

    inline flat_file_string_pool(flat_mmap &file_map_) : file_map(file_map_) {
        pool_string_type s;
        for (s.string_offset = sizeof(offset_type);
             s.string_offset < pool_offset(); s.string_offset += s.string_len(file_map)) {
            pool_cache[s] = s;
        }
    }

    inline pool_string_type pool_store_string(std::string_view v) {
        auto i = pool_cache.find(v);
        if (i != pool_cache.end()) {
            return i->second;
        }
        assert(std::numeric_limits<length_type>::max() >= v.length());
        pool_string_type s;
        s.string_offset = pool_offset();
        if (s.string_offset < sizeof(offset_type)) {
            s.string_offset = sizeof(offset_type);
        }
        auto end_offset = uint64_t(s.string_offset) + sizeof(length_type) + v.length();
        assert(std::numeric_limits<offset_type>::max() >= end_offset);
        file_map.mmap_allocate_at_least(end_offset);
        file_map.mmap_cast<length_type>(s.string_offset) = v.length();
        std::memcpy(s.flat_string_view(file_map).data(), v.data(), v.length());

        pool_offset() = end_offset;
        pool_cache[v] = s;
        return s;
    }
};