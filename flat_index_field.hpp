#pragma once

#include "flat_bytes_field.hpp"
#include "flat_timeshard.hpp"

template<typename key_type, typename... reduce_priority>
decltype(auto) flat_timeshard_field_compare_prepare_key_maybe(key_type *, reduce_priority...) {
    return [](flat_timeshard &, auto &&i) {
        return flat_hash_compare_function_class().compare_prepare_key_maybe<key_type>(i);
    };
}
template<typename key_type, typename... reduce_priority>
decltype(auto) flat_timeshard_field_compare_prepare_key(key_type *, reduce_priority...) {
    return [](flat_timeshard &, auto &&i) {
        return flat_hash_compare_function_class().compare_prepare_key<key_type>(i);
    };
}

struct flat_timeshard_field_comparer {
    flat_timeshard &comparer_timeshard;

    template<typename key_type, typename input_type>
    std::optional<key_type> compare_prepare_key_maybe(input_type &&i) const {
        return flat_timeshard_field_compare_prepare_key_maybe((key_type *) nullptr)(comparer_timeshard, i);
    }
    template<typename key_type, typename input_type>
    key_type compare_prepare_key(input_type &&i) const {
        return flat_timeshard_field_compare_prepare_key((key_type *) nullptr)(comparer_timeshard, i);
    }
};

template<>
decltype(auto) flat_timeshard_field_compare_prepare_key_maybe(flat_bytes_interned_tag *) {
    return [](flat_timeshard &comparer_timeshard, auto &&i) {
        return comparer_timeshard.timeshard_lookup_interned_string(i);
    };
}
template<>
decltype(auto) flat_timeshard_field_compare_prepare_key(flat_bytes_interned_tag *) {
    return [](flat_timeshard &comparer_timeshard, auto &&i) {
        return comparer_timeshard.smap_store_string(i);
    };
}

inline bool flat_hash_compare(
        flat_timeshard_field_comparer const &, flat_bytes_interned_tag const &lhs, flat_bytes_interned_tag const &rhs) {
    return lhs.bytes_offset == rhs.bytes_offset;
}

template<typename key_type>
inline decltype(auto) flat_timeshard_field_key_rehydrate(flat_timeshard_field_comparer &comparer, key_type const &k) {
    return k;
}

template<>
inline decltype(auto) flat_timeshard_field_key_rehydrate(flat_timeshard_field_comparer &comparer, flat_bytes_interned_tag const &k) {
    flat_bytes_interned_tag tag = k;
    return flat_bytes_interned_ptr{comparer.comparer_timeshard, tag}.operator std::string_view();
}

template<typename key_type, typename hash_function = flat_hash_function_class>
struct flat_timeshard_index_field {
    using field_hydrated_key_type = std::decay_t<decltype(flat_timeshard_field_key_rehydrate(std::declval<flat_timeshard_field_comparer &>(), std::declval<const key_type &>()))>;
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

    template<typename timeshard_schema_type, typename walker_type>
    void flat_timeshard_field_walk(walker_type &&walker) {
        using timeshard_type = typename timeshard_schema_type::flat_schema_timeshard;
        using timeshard_iterator_type = typename timeshard_schema_type::flat_schema_timeshard_iterator;
        field_hash.template hash_walk([&](auto &&k, auto &&v) {
            assert(v);
            walker(flat_timeshard_field_key_rehydrate(field_hash.hash_compare_function, k), timeshard_iterator_type(
                                                                                                    reinterpret_cast<timeshard_type *>(&field_hash.hash_compare_function.comparer_timeshard), v - 1));
        });
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


    template<typename lookup_type, typename iterator>
    void index_linked_field_add(lookup_type &&key, iterator const &i) {
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
