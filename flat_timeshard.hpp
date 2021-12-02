#pragma once

#include "cmake_variables.hpp"
#include "flat_dirtree.hpp"
#include "flat_hash.hpp"
#include "flat_macro.hpp"
#include "flat_mmap.hpp"
#include "now_unixtime.hpp"
#include "str.hpp"

struct flat_timeshard_header {
    uint64_t flat_timeshard_magic = 0x666c61746d6d6170;
    uint64_t flat_timeshard_version = 202111140000;
    double flat_timeshard_git_unixtime = flat_git_unixtime;
    uint8_t flat_timeshard_git_sha_string_array[128] = flat_git_sha_string;
    double flat_timeshard_create_unixtime = now_unixtime();

    uint64_t flat_timeshard_index_next = 0;
    uint64_t flat_timeshard_bytes_start_next = sizeof(flat_timeshard_header);
    // TODO: allow all fields to have min/max and monotonic flag
};

struct flat_bytes_offset_tag {
    uint64_t bytes_offset;
};
static_assert(sizeof(flat_bytes_offset_tag) == sizeof(uint64_t));
struct flat_bytes_interned_tag {
    uint64_t bytes_offset;
};
static_assert(sizeof(flat_bytes_interned_tag) == sizeof(uint64_t));


template<typename mmap_field, typename offset_type>
struct flat_bytes_ptr {
    mmap_field &flat_field;
    offset_type flat_bytes_offset;
    using length_type = decltype(flat_field.smap_string_length(0));

    [[nodiscard]] inline operator std::string_view() const {
        auto offset = flat_bytes_offset.bytes_offset;
        if (!offset) {
            return {};
        }

        auto size = flat_field.smap_string_length(flat_bytes_offset.bytes_offset);
        return std::string_view(
                flat_field.smap_string_ptr(offset, size),
                size);
    }

    flat_bytes_ptr &operator=(std::string_view other) requires std::is_reference_v<offset_type> {
        flat_bytes_offset.bytes_offset = flat_field.smap_store_string(other).bytes_offset;
        return *this;
    }
};

template<>
inline uint64_t flat_hash_function(flat_bytes_interned_tag const &k) {
    return flat_hash_function(k.bytes_offset);
}


#define flat_bytes_ptr_op(op)                                                                                                               \
    template<typename mmap, typename offset_type>                                                                                           \
    inline decltype(auto) operator op(std::string_view other, flat_bytes_ptr<mmap, offset_type> const &rhs) {                               \
        return other op(std::string_view) rhs;                                                                                              \
    }                                                                                                                                       \
    template<typename mmap, typename offset_type>                                                                                           \
    inline decltype(auto) operator op(std::string const &other, flat_bytes_ptr<mmap, offset_type> const &rhs) {                             \
        return other op(std::string_view) rhs;                                                                                              \
    }                                                                                                                                       \
    template<typename mmap, typename offset_type>                                                                                           \
    inline decltype(auto) operator op(char const *other, flat_bytes_ptr<mmap, offset_type> const &rhs) {                                    \
        return other op(std::string_view) rhs;                                                                                              \
    }                                                                                                                                       \
    template<typename mmap, typename offset_type>                                                                                           \
    inline decltype(auto) operator op(flat_bytes_ptr<mmap, offset_type> const &lhs, std::string_view other) {                               \
        return (std::string_view) lhs op other;                                                                                             \
    }                                                                                                                                       \
    template<typename lhs_mmap, typename lhs_offset, typename rhs_mmap, typename rhs_offset>                                                \
    inline decltype(auto) operator op(flat_bytes_ptr<lhs_mmap, lhs_offset> const &lhs, flat_bytes_ptr<rhs_mmap, rhs_offset> const &other) { \
        return (std::string_view) lhs op(std::string_view) other;                                                                           \
    }                                                                                                                                       \
    template<typename mmap, typename offset_type>                                                                                           \
    inline decltype(auto) operator op(flat_bytes_ptr<mmap, offset_type> const &lhs, std::string const &other) {                             \
        return (std::string_view) lhs op other;                                                                                             \
    }                                                                                                                                       \
    template<typename mmap, typename offset_type>                                                                                           \
    inline decltype(auto) operator op(flat_bytes_ptr<mmap, offset_type> const &lhs, char const *other) {                                    \
        return (std::string_view) lhs op other;                                                                                             \
    }

flat_bytes_ptr_op(<=>);
flat_bytes_ptr_op(==);
flat_bytes_ptr_op(!=);

template<typename mmap, typename offset>
inline std::ostream &operator<<(std::ostream &os, flat_bytes_ptr<mmap, offset> const &fbs) {
    return os << (std::string_view) fbs;
}

struct flat_timeshard {
    std::string flat_timeshard_name;
    flat_mmap flat_timeshard_main_mmap;
    std::unordered_map<std::string_view, uint64_t> interned_strings;
    char *interned_strings_base;

    flat_timeshard(std::string_view timeshard_name, std::string_view dir, flat_mmap_settings const &settings)
        : flat_timeshard_name(timeshard_name), flat_timeshard_main_mmap(std::string{dir} + "/flat_timeshard_main.flatmap", settings) {
        if (!flat_timeshard_main_mmap.mmap_allocated_len()) {
            flat_timeshard_main_mmap.mmap_allocate_at_least(sizeof(timeshard_header_ref()));
            timeshard_header_ref() = flat_timeshard_header();
        }
        flat_timeshard_header highest_supported_version;
        flat_timeshard_header &lowest_supported_version = highest_supported_version;
        if (highest_supported_version.flat_timeshard_magic != timeshard_header_ref().flat_timeshard_magic) {
            throw std::runtime_error(str("flat_timeshard_magic does not match in timeshard: dir ", dir, " magic ", timeshard_header_ref().flat_timeshard_magic));
        }
        if (timeshard_header_ref().flat_timeshard_version > highest_supported_version.flat_timeshard_version) {
            throw std::runtime_error(str("flat_timeshard_version too new: dir ", dir, " at ", timeshard_header_ref().flat_timeshard_version, ">", highest_supported_version.flat_timeshard_version));
        }
        if (timeshard_header_ref().flat_timeshard_version < lowest_supported_version.flat_timeshard_version) {
            throw std::runtime_error(str("flat_timeshard_version too old: dir ", dir, " at ", timeshard_header_ref().flat_timeshard_version, "<", lowest_supported_version.flat_timeshard_version));
        }
        timeshard_reload_interned_strings();
    }
    flat_timeshard(flat_timeshard const &) = delete;
    flat_timeshard &operator=(flat_timeshard const &) = delete;

    inline flat_timeshard_header &timeshard_header_ref() {
        return flat_timeshard_main_mmap.mmap_cast<flat_timeshard_header>(0);
    }

    void timeshard_commit_index(uint64_t index) {
        if (timeshard_header_ref().flat_timeshard_index_next != index) {
            throw std::runtime_error("timeshard_commit_index index out of order");
        }
        timeshard_header_ref().flat_timeshard_index_next = index + 1;
    }


    uint64_t timeshard_allocate_bytes(uint64_t count) {
        auto ret = timeshard_header_ref().flat_timeshard_bytes_start_next;
        auto new_start = timeshard_header_ref().flat_timeshard_bytes_start_next + count;
        flat_timeshard_main_mmap.mmap_allocate_at_least(new_start);
        if (interned_strings_base != &flat_timeshard_main_mmap.mmap_cast<char>(0)) {
            timeshard_reload_interned_strings();
        }
        timeshard_header_ref().flat_timeshard_bytes_start_next = new_start;
        return ret;
    }

    void timeshard_reload_interned_strings() {
        interned_strings.clear();
        interned_strings_base = &flat_timeshard_main_mmap.mmap_cast<char>(0);
        uint64_t offset = sizeof(flat_timeshard_header);
        while (offset < flat_timeshard_header().flat_timeshard_bytes_start_next) {
            auto tag = flat_bytes_interned_tag{offset};
            auto s = (std::string_view) flat_bytes_ptr<flat_timeshard, flat_bytes_interned_tag>{*this, tag};
            interned_strings[s] = offset;
            offset += s.size() + 1;
        }
    }
    inline char *smap_string_ptr(uint64_t offset, uint64_t size) {
        return &flat_timeshard_main_mmap.mmap_cast<char>(offset + sizeof(smap_string_length(offset)), size);
    }

    std::optional<flat_bytes_interned_tag> timeshard_lookup_interned_string(std::string_view s) {
        if (s.empty()) {
            return flat_bytes_interned_tag{0};
        }
        auto i = interned_strings.find(s);
        if (i != interned_strings.end()) {
            return flat_bytes_interned_tag{i->second};
        }
        return {};
    }

    flat_bytes_interned_tag smap_store_string(std::string_view s) {
        auto already = timeshard_lookup_interned_string(s);
        if (already.has_value()) {
            return already.value();
        }

        auto offset = timeshard_allocate_bytes(s.size() + sizeof(smap_string_length(0)) + 1);
        smap_string_length(offset) = s.size();
        char *p = smap_string_ptr(offset, s.size() + 1);
        std::memcpy(p, s.data(), s.size());
        p[s.size()] = 0;
        interned_strings[s] = offset;
        return flat_bytes_interned_tag{offset};
    }

    inline uint64_t &smap_string_length(uint64_t offset) {
        return flat_timeshard_main_mmap.mmap_cast<uint64_t>(offset);
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

    flat_timeshard_base_field(flat_timeshard &timeshard, std::string const &name, std::string const &dir, flat_mmap_settings const &settings)
        : field_timeshard(timeshard), field_mmap(dir + "/field_" + name + ".flatshard", settings) {
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

    bool operator!() const {
        return !flat_iterator_timeshard;
    }
    operator bool() const {
        return !!*this;
    }

    flat_timeshard_iterator() : flat_iterator_timeshard(nullptr), flat_iterator_index(0) {}

    flat_timeshard_iterator(timeshard_type *timeshard, uint64_t index) : flat_iterator_timeshard{timeshard},
                                                                         flat_iterator_index{index} {}
};
