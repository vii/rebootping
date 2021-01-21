#pragma once

#include "flat_mmap.hpp"
#include "flat_timeshard.hpp"

#include <cstdint>

struct flat_bytes_field {
    uint64_t &flat_bytes_offset;
    flat_timeshard &flat_bytes_timeshard;

    uint64_t &flat_bytes_len() const {
        return flat_bytes_timeshard.flat_timeshard_main_mmap.mmap_cast<uint64_t>(flat_bytes_offset);
    }
    char *flat_bytes_ptr() const {
        auto l = flat_bytes_len();
        return &flat_bytes_timeshard.flat_timeshard_main_mmap.mmap_cast<char>(flat_bytes_offset + sizeof(l), l + 1);
    }

    operator std::string_view() const {
        return std::string_view{reinterpret_cast<char *>(flat_bytes_ptr()), flat_bytes_len()};
    }
    flat_bytes_field &operator=(std::string_view other) {
        auto offset = flat_bytes_timeshard.timeshard_allocate_bytes(sizeof(flat_bytes_len()) + other.size() + 1);
        auto new_field = flat_bytes_field{offset, flat_bytes_timeshard};
        new_field.flat_bytes_len() = other.size();
        std::memcpy(new_field.flat_bytes_ptr(), other.data(), other.size());
        new_field.flat_bytes_ptr()[other.size()] = 0;
        flat_bytes_offset = offset;
        return *this;
    }
};


#define flat_bytes_field_op(op)                                                                     \
    inline decltype(auto) operator op(std::string_view other, flat_bytes_field const &rhs) {        \
        return other op(std::string_view) rhs;                                                      \
    }                                                                                               \
    inline decltype(auto) operator op(std::string const &other, flat_bytes_field const &rhs) {      \
        return other op(std::string_view) rhs;                                                      \
    }                                                                                               \
    inline decltype(auto) operator op(flat_bytes_field const &lhs, std::string_view other) {        \
        return (std::string_view) lhs op other;                                                     \
    }                                                                                               \
    inline decltype(auto) operator op(flat_bytes_field const &lhs, flat_bytes_field const &other) { \
        return (std::string_view) lhs op(std::string_view) other;                                   \
    }                                                                                               \
    inline decltype(auto) operator op(flat_bytes_field const &lhs, std::string const &other) {      \
        return (std::string_view) lhs op other;                                                     \
    }

flat_bytes_field_op(<=>);
flat_bytes_field_op(==);
flat_bytes_field_op(!=);

inline std::ostream &operator<<(std::ostream &os, flat_bytes_field const &fbs) {
    return os << (std::string_view) fbs;
}

template<>
struct flat_timeshard_field<std::string_view> : flat_timeshard_base_field<uint64_t> {
    using flat_timeshard_base_field<uint64_t>::flat_timeshard_base_field;

    inline flat_bytes_field operator[](uint64_t index) {
        return flat_bytes_field{
                field_mmap.mmap_cast<uint64_t>(index * sizeof(uint64_t)),
                field_timeshard};
    }
};
