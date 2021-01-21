#pragma once

#include "cmake_variables.hpp"
#include "flat_dirtree.hpp"
#include "flat_macro.hpp"
#include "flat_mmap.hpp"
#include "now_unixtime.hpp"

struct flat_timeshard_header {
    uint64_t flat_file_magic = 0x666c61746d6d6170;
    uint64_t flat_file_version = 2020122100;
    double flat_git_timestamp = flat_git_timestamp;
    uint8_t flat_git_sha_string_array[128] = flat_git_sha_string;
    double flat_create_timestamp = now_unixtime();

    uint64_t flat_index_next = 0;
    uint64_t flat_bytes_start_next = sizeof(flat_timeshard_header);
    // TODO: allow all fields to have min/max and monotonic flag
};

struct flat_timeshard {
    std::string flat_timeshard_name;
    flat_mmap flat_timeshard_main_mmap;

    flat_timeshard(std::string_view timeshard_name, std::string_view dir, flat_mmap_settings const &settings)
        : flat_timeshard_name(timeshard_name), flat_timeshard_main_mmap(std::string{dir} + "/flat_timeshard_main.flatmap", settings) {
    }

    inline flat_timeshard_header &timeshard_header_ref() {
        return flat_timeshard_main_mmap.mmap_cast<flat_timeshard_header>(0);
    }

    void timeshard_commit_index(uint64_t index) {
        if (timeshard_header_ref().flat_index_next != index) {
            throw std::runtime_error("committing index out of order");
        }
        timeshard_header_ref().flat_index_next = index + 1;
    }

    void timeshard_reset_header() {
        timeshard_header_ref() = flat_timeshard_header();
    }

    uint64_t timeshard_allocate_bytes(uint64_t count) {
        auto ret = timeshard_header_ref().flat_bytes_start_next;
        timeshard_header_ref().flat_bytes_start_next += count;
        flat_timeshard_main_mmap.mmap_allocate_at_least(timeshard_header_ref().flat_bytes_start_next);
        return ret;
    }
};

template<typename field_type>
constexpr size_t flat_field_sizeof() {
    return sizeof(field_type);
}

template<typename field_type>
struct flat_timeshard_field_schema {
    using field_value_type = field_type;
};

template<typename... field_schemas>
struct flat_timeshard_schema {
    std::tuple<field_schemas...> flat_schema_fields;
};

template<typename field_type>
struct flat_timeshard_base_field {
    flat_timeshard &field_timeshard;
    flat_mmap field_mmap;

    flat_timeshard_base_field(flat_timeshard &timeshard, std::string const &filename, flat_mmap_settings const &settings)
        : field_timeshard(timeshard), field_mmap(filename, settings) {
    }

    void flat_timeshard_ensure_field_mmapped(uint64_t index) {
        field_mmap.mmap_allocate_at_least((index + 1) * flat_field_sizeof<field_type>());
    }
};

template<typename field_type>
struct flat_timeshard_field : flat_timeshard_base_field<field_type> {
    using flat_timeshard_base_field<field_type>::flat_timeshard_base_field;
    using flat_timeshard_base_field<field_type>::field_mmap;

    inline field_type &operator[](uint64_t index) {
        return field_mmap.template mmap_cast<field_type>(index * sizeof(field_type));
    }
};


template<typename timeshard_type>
struct flat_timeshard_iterator {
    timeshard_type *flat_iterator_timeshard;
    uint64_t flat_iterator_index;

    flat_timeshard_iterator(timeshard_type *timeshard, uint64_t index) : flat_iterator_timeshard{timeshard},
                                                                         flat_iterator_index{index} {}
};
