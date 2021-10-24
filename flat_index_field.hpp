#pragma once

#include "flat_timeshard.hpp"

using flat_timeshard_index_field_base = flat_timeshard_field<uint64_t>;

template<typename key_type, typename hash_function = flat_hash_function_class>
struct flat_timeshard_index_field : flat_timeshard_index_field_base {
    flat_hash<key_type, uint64_t, hash_function> field_hash;

    flat_timeshard_index_field(flat_timeshard &timeshard, std::string const &name, std::string const &dir, flat_mmap_settings const &settings)
        : flat_timeshard_index_field_base(timeshard, name, dir, settings),
          field_hash(dir + "/field_" + name + ".flathash", settings) {}


    void flat_timeshard_ensure_field_mmapped(uint64_t index) {
        flat_timeshard_index_field_base::flat_timeshard_ensure_field_mmapped(index);
        field_hash.hash_mmap.mmap_allocate_at_least(1);
    }

    [[nodiscard]] uint64_t *flat_timeshard_index_lookup_key(const key_type &k) const {
        return field_hash.hash_find_key(k);
    }

    template<typename iterator>
    void index_add(const key_type &key, iterator const &i) {
        auto index = i.flat_iterator_index;
        auto &v = field_hash.hash_add_key(key);
        if (v) {
            (*this)[index] = v;
        }
        v = index + 1;
    }
};

template<typename key_type, typename hash_function = flat_hash_function_class>
struct flat_index_field {};

template<typename key_type, typename hash_function>
struct flat_timeshard_field<flat_index_field<key_type, hash_function>> : flat_timeshard_index_field<key_type, hash_function> {
    using flat_timeshard_index_field<key_type, hash_function>::flat_timeshard_index_field;
    flat_timeshard_field& operator()() {
         return *this;
    }
};
