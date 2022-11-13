#pragma once

#include "flat_mmap.hpp"
#include "flat_timeshard.hpp"

#include <cstdint>

struct flat_smap_header {
    uint64_t flat_smap_magic = 0x666c6174736d6170;
    uint64_t flat_smap_version = 202111140000;
    double flat_smap_git_unixtime = flat_git_unixtime;
    uint8_t flat_smap_git_sha_string_array[128] = flat_git_sha_string;
    double flat_smap_create_unixtime = now_unixtime();

    uint64_t flat_smap_offset_next = sizeof(flat_smap_header);
    // TODO: allow all fields to have min/max and monotonic flag
};

struct flat_timeshard_field_bytes_base : flat_timeshard_base_field<flat_bytes_offset_tag> {
    using length_type = uint64_t;
    flat_mmap flat_smap;

    flat_timeshard_field_bytes_base(flat_timeshard &timeshard, std::string const &name, std::string const &dir, flat_mmap_settings const &settings)
        : flat_timeshard_base_field<flat_bytes_offset_tag>(timeshard, name, dir, settings), flat_smap(dir + "/field_" + name + ".flatsmap", settings) {
        if (!flat_smap.mmap_allocated_len()) {
            flat_smap.mmap_allocate_at_least(sizeof(flat_smap_header_ref()));
            flat_smap_header_ref() = flat_smap_header();
        }
        flat_smap_header highest_supported_version;
        if (highest_supported_version.flat_smap_magic != flat_smap_header_ref().flat_smap_magic) {
            throw std::runtime_error(
                    str("flat_smap_magic does not match in smap: ", flat_smap.flat_mmap_filename(), " magic ", flat_smap_header_ref().flat_smap_magic));
        }
        if (flat_smap_header_ref().flat_smap_version > highest_supported_version.flat_smap_version) {
            throw std::runtime_error(str("flat_smap_version too new: smap ", flat_smap.flat_mmap_filename(), " at ", flat_smap_header_ref().flat_smap_version, ">",
                                         highest_supported_version.flat_smap_version));
        }
        if (flat_smap_header_ref().flat_smap_offset_next > flat_smap.mmap_allocated_len()) {
            throw std::runtime_error(str("flat_smap_offset_next too big: smap ", flat_smap.flat_mmap_filename(), " at ", flat_smap_header_ref().flat_smap_offset_next,
                                         ">", flat_smap.mmap_allocated_len()));
        }
    }

    flat_smap_header &flat_smap_header_ref() { return flat_smap.mmap_cast<flat_smap_header>(0); }

    uint64_t smap_allocate_bytes(uint64_t bytes) {
        auto offset = flat_smap_header_ref().flat_smap_offset_next;
        auto required_len = offset + bytes;
        flat_smap.mmap_allocate_at_least(required_len);
        flat_smap_header_ref().flat_smap_offset_next = required_len;
        return offset;
    }

    inline length_type &smap_string_length(uint64_t offset) { return flat_smap.mmap_cast<length_type>(offset); }

    inline char *smap_string_ptr(uint64_t offset, uint64_t size) { return &flat_smap.mmap_cast<char>(offset + sizeof(length_type), size); }

    inline flat_bytes_offset_tag smap_store_string(std::string_view s) {
        if (s.empty()) {
            return flat_bytes_offset_tag{0};
        }
        uint64_t offset = smap_allocate_bytes(s.size() + 1 + sizeof(length_type));
        smap_string_length(offset) = s.size();
        char *p = &flat_smap.mmap_cast<char>(offset + sizeof(length_type), s.size() + 1);
        std::memcpy(p, s.data(), s.size());
        p[s.size()] = 0;
        return flat_bytes_offset_tag{offset};
    }
};

template<>
struct flat_timeshard_field<std::string_view> : flat_timeshard_field_bytes_base {
    using flat_timeshard_field_bytes_base::flat_timeshard_field_bytes_base;

    inline auto operator[](uint64_t index) const {
        return flat_bytes_ptr<flat_timeshard_field<std::string_view>, flat_bytes_offset_tag &>{
                // TODO create distinction between a writeable flat_bytes_ptr and a const one
                const_cast<flat_timeshard_field<std::string_view> &>(*this), field_mmap.mmap_cast<flat_bytes_offset_tag>(index * sizeof(flat_bytes_offset_tag))};
    }
};

using flat_bytes_interned_ptr = flat_bytes_ptr<flat_timeshard, flat_bytes_interned_tag &>;
using flat_bytes_const_interned_ptr = flat_bytes_ptr<flat_timeshard, flat_bytes_interned_tag const &>;
using flat_bytes_field_ptr = flat_bytes_ptr<flat_timeshard_field<std::string_view>, flat_bytes_offset_tag &>;

template<>
struct flat_timeshard_field<flat_bytes_interned_ptr> : flat_timeshard_base_field<flat_bytes_offset_tag> {
    using flat_timeshard_base_field<flat_bytes_offset_tag>::flat_timeshard_base_field;

    inline flat_bytes_interned_ptr operator[](uint64_t index) const {
        return flat_bytes_interned_ptr{field_timeshard, field_mmap.mmap_cast<flat_bytes_interned_tag>(index * sizeof(flat_bytes_interned_tag))};
    }
};
