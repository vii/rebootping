#pragma once

#include "flat_bytes_field.hpp"
#include "flat_timeshard.hpp"

struct flat_timeshard_field_comparer {
    flat_timeshard &comparer_timeshard;
};

inline bool flat_hash_compare(
        flat_timeshard_field_comparer const &, flat_bytes_interned_tag const &lhs, flat_bytes_interned_tag const &rhs) {
    return lhs.bytes_offset == rhs.bytes_offset;
}


template<>
[[nodiscard]] inline decltype(auto) flat_hash_prepare_key_maybe<flat_bytes_interned_tag, flat_timeshard_field_comparer>(flat_timeshard_field_comparer const &comparer) {
    return [&](std::string_view input) -> std::optional<flat_bytes_interned_tag> {
        return comparer.comparer_timeshard.timeshard_lookup_interned_string(input);
    };
}

template<>
[[nodiscard]] inline decltype(auto) flat_hash_prepare_key<flat_bytes_interned_tag, flat_timeshard_field_comparer>(flat_timeshard_field_comparer const &comparer) {
    return [&](auto const &input) {
        return comparer.comparer_timeshard.smap_store_string(input);
    };
}

template<typename key_type, typename hash_function = flat_hash_function_class>
struct flat_timeshard_index_field {
    flat_hash<key_type, uint64_t, hash_function, flat_timeshard_field_comparer> field_hash;
    flat_timeshard_index_field(flat_timeshard &timeshard, std::string const &name, std::string const &dir, flat_mmap_settings const &settings)
        : field_hash(dir + "/field_" + name + ".flathash", settings, flat_timeshard_field_comparer{timeshard}) {}

    void flat_timeshard_ensure_field_mmapped(uint64_t index) {
        field_hash.hash_mmap.mmap_allocate_at_least(1);
    }
    template<typename lookup_type>
    [[nodiscard]] uint64_t *flat_timeshard_index_lookup_key(lookup_type &&k) const {
        return field_hash.hash_find_key(k);
    }
    template<typename lookup_type, typename iterator>
    void flat_timeshard_index_set_key(lookup_type &&key, iterator const &i) {
        field_hash.hash_add_key(key) = i.flat_iterator_index + 1;
    }
};

using flat_timeshard_index_linked_field_base = flat_timeshard_field<uint64_t>;


template<typename key_type, typename hash_function = flat_hash_function_class>
struct flat_timeshard_index_linked_field : flat_timeshard_index_linked_field_base, flat_timeshard_index_field<key_type, hash_function> {
    using flat_timeshard_index_field<key_type, hash_function>::field_hash;
    flat_timeshard_index_linked_field(flat_timeshard &timeshard, std::string const &name, std::string const &dir, flat_mmap_settings const &settings)
        : flat_timeshard_index_linked_field_base(timeshard, name, dir, settings),
          flat_timeshard_index_field<key_type, hash_function>(timeshard, name, dir, settings) {}

    void flat_timeshard_ensure_field_mmapped(uint64_t index) {
        flat_timeshard_index_linked_field_base::flat_timeshard_ensure_field_mmapped(index);
        flat_timeshard_index_field<key_type, hash_function>::flat_timeshard_ensure_field_mmapped(index);
    }


    template<typename iterator>
    void index_linked_field_add(const key_type &key, iterator const &i) {
        auto index = i.flat_iterator_index;
        auto &v = field_hash.hash_add_key(key);
        (*this)[index] = v;
        v = index + 1;
    }
};

template<typename key_type, typename hash_function = flat_hash_function_class>
struct flat_index_field {};

template<typename key_type, typename hash_function>
struct flat_timeshard_field<flat_index_field<key_type, hash_function>> : flat_timeshard_index_field<key_type, hash_function> {
    using flat_timeshard_index_field<key_type, hash_function>::flat_timeshard_index_field;
    flat_timeshard_field &operator()() {
        return *this;
    }
    uint64_t operator[](uint64_t) const {
        return 0;
    }
};


template<typename key_type, typename hash_function = flat_hash_function_class>
struct flat_index_linked_field {};


template<typename key_type, typename hash_function>
struct flat_timeshard_field<flat_index_linked_field<key_type, hash_function>> : flat_timeshard_index_linked_field<key_type, hash_function> {
    using flat_timeshard_index_linked_field<key_type, hash_function>::flat_timeshard_index_linked_field;
    flat_timeshard_field &operator()() {
        return *this;
    }
};
