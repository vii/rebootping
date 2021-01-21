#pragma once

#include <string_view>

#include "flat_mmap.hpp"

template<typename offset_type, typename length_type>
struct flat_file_string {
    offset_type string_offset;

    inline length_type string_len(flat_mmap const &map) const {
        return map.mmap_cast<length_type>(string_offset);
    }

    inline std::string_view flat_string_view(flat_mmap const &map) {
        auto len = string_len(map);
        return std::string_view(&map.mmap_cast<char>(string_offset + sizeof(length_type), len), len);
    }
} __attribute__((packed));
