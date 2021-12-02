#include "flat_index_field.hpp"
#include "flat_record.hpp"
#include "rebootping_test.hpp"

define_flat_record(string_index_record,
                   (uint64_t, thirteen),
                   (flat_bytes_mutable_interned_ptr, seven),
                   (flat_index_field<flat_bytes_interned_tag>, string_index));

TEST(flat_index_field_suite, some_strings) {
    tmpdir tmpdir;
    string_index_record records(tmpdir.tmpdir_name);
    const double unixtime = 1;
    auto r = records.string_index("hello").add_if_missing(unixtime);
    // options
    // intern all strings: no go as can't store network content
    // intern some strings: where to put them??
    // - linked list in main mmap
    // - flag interned in main mmap
    // - hash in another mmap
    // Total number of interned strings: e.g. ten. Total number of uninterned strings: many (millions)?
    // Therefore: keep the interned strings away from the other ones, no need for complex data structure.
}

define_flat_record(int_index_record,
                   (uint64_t, thirteen),
                   (uint8_t, seven),
                   (flat_index_field<uint32_t>, uint32_index),
                   (flat_index_field<uint64_t>, uint64_index));

TEST(flat_index_field_suite, just_ints) {
    tmpdir tmpdir;
    int_index_record records(tmpdir.tmpdir_name);
    const double unixtime = 1;
    const int max_i = 1017 * 1013;
    auto index_lookup = [](int i) {
        return ~((uint32_t) i) * 0xdeadbeef;
    };

    for (int i = 0; max_i > i; ++i) {
        auto r = records.uint32_index(index_lookup(i)).add_if_missing(unixtime);
        r.thirteen() = i * 13;
        r.seven() = i * 7;
        records.uint64_index(index_lookup(i)).set_index(r);
    };

    for (int i = 0; max_i > i; ++i) {
        auto r = *records.uint32_index(index_lookup(i)).begin();
        rebootping_test_check(r.thirteen(), ==, i * 13);
        rebootping_test_check(r.seven(), ==, (uint8_t) (i * 7));

        auto again = *records.uint64_index(index_lookup(i)).begin();
        rebootping_test_check(r, ==, again);
    }
}
