#pragma once

#include "escape_json.hpp"
#include "flat_timeshard.hpp"

template<typename function, typename holder>
inline decltype(auto) flat_record_apply_per_field(function &&f, holder &&record) {
    return std::apply([&](auto &&...field) {
        (f(field, record), ...);
    },
                      typename std::decay_t<holder>::flat_timeshard_schema_type().flat_schema_fields);
};

template<typename holder>
inline void flat_record_dump_as_json(std::ostream &os, holder &&record) {
    os << "{";
    bool first = true;
    flat_record_apply_per_field([&](auto &&field, auto &&record) {
        if (!first) {
            os << ", ";
        }
        os << escape_json(field.flat_field_name()) << ": " << escape_json(field.flat_field_value(record));
        first = false;
    },
                                record);
    os << "}";
}

#define flat_timeshard_field_constructor(kind, name) \
    , name(*this, #name, dir, settings)
#define flat_timeshard_field_declaration(kind, name) \
    flat_timeshard_field<kind> name;
#define flat_timeshard_iterator_member(kind, name) \
    inline decltype(auto) name() { return flat_iterator_timeshard->name[flat_iterator_index]; }
#define flat_timeshard_ensure_field_mmapped_statement(kind, name) \
    name.flat_timeshard_ensure_field_mmapped(len);
#define flat_timeshard_field_schema_declaration(kind, name)                              \
    struct name : flat_timeshard_field_schema<kind> {                                    \
        char const *flat_field_name() { return #name; }                                  \
        char const *flat_field_type_string() { return #kind; }                           \
        template<typename holder_type>                                                   \
        decltype(auto) flat_field_value(holder_type &&holder) { return holder.name(); }; \
    };

#define flat_timeshard_field_schema_name(kind, name) name

#define flat_record_query_member(kind, name)                                                                   \
    template<typename key_type>                                                                                \
    decltype(auto)                                                                                             \
    name(key_type const &iter_key,                                                                             \
         double start_unixtime = std::numeric_limits<double>::min(),                                           \
         double end_unixtime = std::numeric_limits<double>::max()) {                                           \
        return dirtree_field_query(iter_key, start_unixtime, end_unixtime, [](auto &&v)->auto& { return v.name(); }); \
    }

#define define_flat_record(record_name, ...)                                                                                                                                                                                                                                               \
    struct flat_record_schema_##record_name {                                                                                                                                                                                                                                              \
        evaluate_for_each(flat_timeshard_field_schema_declaration, __VA_ARGS__)                                                                                                                                                                                                            \
                                                                                                                                                                                                                                                                                           \
                struct flat_timeshard_schema_type : flat_timeshard_schema<evaluate_for_each_comma(flat_timeshard_field_schema_name, __VA_ARGS__)> {                                                                                                                                        \
            char const *flat_schema_name() { return #record_name; }                                                                                                                                                                                                                        \
        };                                                                                                                                                                                                                                                                                 \
    };                                                                                                                                                                                                                                                                                     \
                                                                                                                                                                                                                                                                                           \
    struct flat_timeshard_iterator_##record_name;                                                                                                                                                                                                                                          \
                                                                                                                                                                                                                                                                                           \
    struct flat_timeshard_##record_name : flat_timeshard {                                                                                                                                                                                                                                 \
        using flat_timeshard_schema_type = flat_record_schema_##record_name::flat_timeshard_schema_type;                                                                                                                                                                                   \
                                                                                                                                                                                                                                                                                           \
        evaluate_for_each(flat_timeshard_field_declaration, __VA_ARGS__)                                                                                                                                                                                                                   \
                                                                                                                                                                                                                                                                                           \
                void flat_timeshard_ensure_mmapped(uint64_t len) {                                                                                                                                                                                                                         \
            evaluate_for_each(flat_timeshard_ensure_field_mmapped_statement, __VA_ARGS__)                                                                                                                                                                                                  \
        }                                                                                                                                                                                                                                                                                  \
                                                                                                                                                                                                                                                                                           \
        inline flat_timeshard_##record_name(std::string_view timeshard_name, std::string const &dir, flat_mmap_settings const &settings)                                                                                                                                                   \
            : flat_timeshard(timeshard_name, dir, settings)                                                                                                                                                                                                                                \
                      evaluate_for_each(flat_timeshard_field_constructor, __VA_ARGS__) {}                                                                                                                                                                                                  \
        flat_timeshard_iterator_##record_name timeshard_iterator_at(uint64_t index);                                                                                                                                                                                                       \
    };                                                                                                                                                                                                                                                                                     \
                                                                                                                                                                                                                                                                                           \
                                                                                                                                                                                                                                                                                           \
    struct flat_timeshard_iterator_##record_name : flat_timeshard_iterator<flat_timeshard_##record_name> {                                                                                                                                                                                 \
        using flat_timeshard_schema_type = flat_record_schema_##record_name::flat_timeshard_schema_type;                                                                                                                                                                                   \
                                                                                                                                                                                                                                                                                           \
        using flat_timeshard_iterator<flat_timeshard_##record_name>::flat_timeshard_iterator;                                                                                                                                                                                              \
                                                                                                                                                                                                                                                                                           \
        evaluate_for_each(flat_timeshard_iterator_member, __VA_ARGS__)                                                                                                                                                                                                                     \
    };                                                                                                                                                                                                                                                                                     \
                                                                                                                                                                                                                                                                                           \
    inline flat_timeshard_iterator_##record_name flat_timeshard_##record_name ::timeshard_iterator_at(uint64_t index) {                                                                                                                                                                    \
        return flat_timeshard_iterator_##record_name(this, index);                                                                                                                                                                                                                         \
    }                                                                                                                                                                                                                                                                                      \
    struct record_name : flat_dirtree<flat_timeshard_##record_name, flat_timeshard_iterator_##record_name> {                                                                                                                                                                               \
        using flat_timeshard_schema_type = flat_record_schema_##record_name::flat_timeshard_schema_type;                                                                                                                                                                                   \
        using flat_record_schema_type = flat_record_schema_##record_name;                                                                                                                                                                                                                  \
        evaluate_for_each(flat_record_query_member, __VA_ARGS__) explicit record_name(std::string_view dir, flat_mmap_settings const &settings = flat_mmap_settings()) : flat_dirtree<flat_timeshard_##record_name, flat_timeshard_iterator_##record_name>(dir, #record_name, settings) {} \
    }


define_flat_record(flat_records_test_macro_definitions,
                   (int64_t, i), (double, d), (std::u8string_view, s));

inline void flat_records_test_macro_definitions_instantiate(flat_records_test_macro_definitions &records) {
    for (auto record : records.timeshard_query()) {
        flat_record_apply_per_field([](auto &&field, auto &&record) {
            field.flat_field_value(record);
        },
                                    record);
    }
}
