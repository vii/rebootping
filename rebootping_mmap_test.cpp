#include "escape_json.hpp"
#include "flat_bytes_field.hpp"
#include "flat_hash.hpp"
#include "flat_record.hpp"
#include "str.hpp"

#include <functional>
#include <iostream>
#include <string>
#include <vector>

std::vector<std::pair<std::string, std::function<void()>>> rebootping_tests;

#define TEST(suite_name, test_name)                                                                                                                     \
    void suite_name##_##test_name();                                                                                                                    \
    namespace {                                                                                                                                         \
        auto rebootping_test_register_##suite_name##_##test_name = rebootping_tests.emplace_back(#suite_name "_" #test_name, suite_name##_##test_name); \
    }                                                                                                                                                   \
    void suite_name##_##test_name()

struct tmpdir {
    std::string tmpdir_name;

    tmpdir() {
        tmpdir_name = std::filesystem::temp_directory_path().string() + "/rebootping_test.XXXXXX";
        CALL_ERRNO_BAD_VALUE(mkdtemp, nullptr, tmpdir_name.data());// can modify since C++11
    }

    ~tmpdir() {
        for (auto &i : std::filesystem::recursive_directory_iterator(tmpdir_name)) {
            std::cout << "tmpdir " << (i.is_regular_file() ? i.file_size() : 0) << '\t' << i.path() << std::endl;
        }
        auto removed_count = std::filesystem::remove_all(tmpdir_name);
        std::cout << "tmpdir cleaned " << tmpdir_name << " " << removed_count << std::endl;
    }
};

TEST(flat_hash_suite, hash_instantiate) {
    tmpdir tmpdir;
    struct example_struct {
        unsigned a;
        unsigned b;
    };

    auto hash = flat_hash<uint64_t, uint64_t>(tmpdir.tmpdir_name + "/hash_instantiate_u64_u64.flatmap");
    auto another = flat_hash<uint16_t, example_struct>(tmpdir.tmpdir_name + "/hash_instantiate_u16_example.flatmap");
}

TEST(flat_hash_suite, hash_ints) {

    for (unsigned count = 1; count < 1024 * 1024 * 1024; count *= 19) {
        tmpdir tmpdir;

        auto hash = flat_hash<uint64_t, uint64_t>(tmpdir.tmpdir_name + "/hash_ints_test.flatmap");
        for (unsigned n = 0; count > n; ++n) {
            assert(!hash.hash_find_key(n));
        }

        auto h = [](unsigned n) { return ~n * 17 + n * -13; };

        for (unsigned n = 0; count > n; ++n) {
            *hash.hash_add_key(n) = h(n);
        }
        for (unsigned n = 0; count > n; ++n) {
            assert(*hash.hash_find_key(n) == h(n));
        }
        assert(!hash.hash_find_key(count));
    }
}

define_flat_record(all_numbers_records,
                   (int8_t, i8),
                   (int16_t, i16),
                   (int32_t, i32),
                   (int64_t, i64),
                   (uint8_t, u8),
                   (uint16_t, u16),
                   (uint32_t, u32),
                   (uint64_t, u64),
                   (float, f),
                   (double, d), );

define_flat_record(just_one_byte_records,
                   (uint8_t, u8), );

define_flat_record(strings_records,
                   (std::string_view, s0),
                   (std::string_view, s1), );

define_flat_record(all_kinds_records,
                   (int8_t, i8),
                   (int16_t, i16),
                   (int32_t, i32),
                   (int64_t, i64),
                   (uint8_t, u8),
                   (uint16_t, u16),
                   (uint32_t, u32),
                   (uint64_t, u64),
                   (float, f),
                   (double, d),
                   (std::string_view, s), );

int64_t simple_hash(std::string_view s) {
    int64_t ret = s.size() * ((int64_t{1} << 62) - 57);

    for (auto c : s) {
        ret ^= -int64_t{c} * ((int64_t{1} << 62) - 87);
        ret *= (int64_t{1} << 62) - 117;
    }
    return ret;
}

template<typename field_type>
decltype(auto) row_generator_all_kinds_value(uint64_t row_num, std::string_view field_name) {
    return (field_type)(row_num ^ simple_hash(field_name));
}

template<>
decltype(auto) row_generator_all_kinds_value<flat_bytes_field>(uint64_t row_num, std::string_view field_name) {
    return str(field_name, row_num);
}

auto row_generator_all_kinds_records = [](uint64_t row_num, auto &&field, auto &&value) {
    using field_type = std::decay_t<decltype(value)>;
    return row_generator_all_kinds_value<field_type>(row_num, field.flat_field_name());
};


template<typename record_type, typename row_generator>
void test_flat_read_write(
        std::string_view test_name, row_generator &&rg, uint64_t row_count,
        std::function<std::string(uint64_t)> shard_name = [](uint64_t row_num) {
            return "20210107";
        }) {
    tmpdir tmpdir;
    record_type test_records{tmpdir.tmpdir_name};

    for (uint64_t row_num = 0; row_count > row_num; ++row_num) {
        test_records.add_flat_record(shard_name(row_num), [&](auto &&i) {
            flat_record_apply_per_field([&](auto &&field, auto &&record) {
                field.flat_field_value(record) = rg(row_num, field, field.flat_field_value(record));
            },
                                        i);
        });
    }

    uint64_t row_num = 0;
    uint64_t incorrect = 0;
    std::unordered_map<std::string, uint64_t> correct_field;
    for (auto record : test_records.timeshard_query()) {
        flat_record_apply_per_field([&](auto &&field, auto &&record) {
            auto actual_value = field.flat_field_value(record);
            auto proper_value = rg(row_num, field, field.flat_field_value(record));
            if (proper_value != actual_value) {
                std::cerr << "test_flat_read_write " << test_name << " row " << row_num << " field "
                          << field.flat_field_name() << " is set to " << actual_value << " but need " << proper_value
                          << std::endl;
                ++incorrect;
            } else {
                ++correct_field[field.flat_field_name()];
            }
        },
                                    record);
        ++row_num;
    }

    std::cout << "test_flat_read_write " << test_name << " checked " << row_num << "/" << row_count << " rows"
              << std::endl;
    for (auto &[k, v] : correct_field) {
        if (v != row_count) {
            std::cout << "test_flat_read_write " << test_name << " field " << k << " correct " << v << "/" << row_count
                      << " rows" << std::endl;
        }
    }

    assert(row_num == row_count);
    assert(!incorrect);
}

template<typename records_type>
std::string string_serialise_records(records_type &records) {
    std::ostringstream oss;
    for (auto record : records.timeshard_query()) {
        oss << "{";
        bool first = true;
        flat_record_apply_per_field([&](auto &&field, auto &&record) {
            if (!first) {
                oss << ", ";
            }
            oss << escape_json(field.flat_field_name()) << ": " << escape_json(field.flat_field_value(record));
            first = false;
        },
                                    record);
        oss << "}" << std::endl;
    }
    return oss.str();
}

TEST(flat_records, check_serialisation) {
    tmpdir tmpdir;
    char const *expected = R"({"i8": 65, "i16": -15581, "i32": 1527868653, "i64": "-9223372022431611104", "u8": 13, "u16": 60255, "u32": "3327372177", "u64": 9223372053062609372, "f": 9.223372036854776e+18, "d": 9.223372036855788e+18, "s": "s0"}
{"i8": 64, "i16": -15582, "i32": 1527868652, "i64": "-9223372022431611103", "u8": 12, "u16": 60254, "u32": "3327372176", "u64": 9223372053062609373, "f": 9.223372036854776e+18, "d": 9.223372036855788e+18, "s": "s1"}
{"i8": 67, "i16": -15583, "i32": 1527868655, "i64": "-9223372022431611102", "u8": 15, "u16": 60253, "u32": "3327372179", "u64": 9223372053062609374, "f": 9.223372036854776e+18, "d": 9.223372036855788e+18, "s": "s2"}
)";
    uint64_t row_count = 3;

    {
        all_kinds_records test_records{tmpdir.tmpdir_name};
        for (
                uint64_t row_num = 0;
                row_count >
                row_num;
                ++row_num) {
            test_records.add_flat_record("20200107", [&](
                                                             auto &&i) {
                flat_record_apply_per_field([&](
                                                    auto &&field,
                                                    auto &&record) {
                    field.flat_field_value(record) = row_generator_all_kinds_records(row_num, field, field.flat_field_value(record));
                },
                                            i);
            });
        }
        auto after_write = string_serialise_records(test_records);
        all_kinds_records reopen_records{tmpdir.tmpdir_name};
        auto reopen = string_serialise_records(reopen_records);
        std::cout << "after_write: " << after_write << std::endl
                  << "reopen: " << reopen << std::endl;
        assert(after_write == reopen);
        assert(reopen == expected);
    }
    all_kinds_records reopen_records{tmpdir.tmpdir_name};
    auto reopen = string_serialise_records(reopen_records);
    assert(reopen == expected);
}

TEST(flat_records, all_values) {
    test_flat_read_write<all_kinds_records>("all_values", row_generator_all_kinds_records, 7);
}

TEST(flat_records, some_strings) {
    for (uint64_t rows = 1; rows < 100 * 1024 * 1024; rows *= 7) {
        test_flat_read_write<strings_records>(
                str("some_strings", rows),
                [](
                        uint64_t row_num,
                        auto &&field,
                        auto &&value) {
                    return str("string_example", field.

                                                 flat_field_name(),
                               row_num

                    );
                },
                rows);
    }
}

TEST(flat_records, just_bytes) {
    for (
            uint64_t rows = 1;
            rows < 100 * 1024 * 1024; rows *= 8) {
        test_flat_read_write<just_one_byte_records>(
                str("just_bytes", rows),
                [](
                        uint64_t row_num,
                        auto &&field,
                        auto &&value) {
                    return 61;
                },
                rows);
    }
}

TEST(flat_records, all_numbers) {
    for (
            uint64_t rows = 1;
            rows < 100 * 1024 * 1024; rows *= 2) {
        test_flat_read_write<all_numbers_records>(
                str("row_number", rows),
                [](
                        uint64_t row_num,
                        auto &&field,
                        auto &&value) {
                    using field_type = std::decay_t<decltype(value)>;
                    return (field_type)
                            row_num;
                },
                rows);
        test_flat_read_write<all_numbers_records>(
                str("row_number", rows + 1),
                [](
                        uint64_t row_num,
                        auto &&field,
                        auto &&value) {
                    using field_type = std::decay_t<decltype(value)>;
                    return (field_type)
                            row_num;
                },
                rows + 1);
    }

    test_flat_read_write<all_numbers_records>(
            "numeric_limits_max", [](uint64_t row_num, auto &&field, auto &&value) {
                using field_type = std::decay_t<decltype(value)>;
                return

                        std::numeric_limits<field_type>::max();
            },
            919);
    test_flat_read_write<all_numbers_records>(
            "numeric_limits_min", [](uint64_t row_num, auto &&field, auto &&value) {
                using field_type = std::decay_t<decltype(value)>;
                return

                        std::numeric_limits<field_type>::min();
            },
            2047);
}


int main() {
    for (auto &[name, f] : rebootping_tests) {
        std::cout << "rebooting_running_test " << name << std::endl;
        f();
        std::cout << "rebootping_test_done " << name << std::endl;
    }
}