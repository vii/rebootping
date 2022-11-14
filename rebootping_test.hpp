#pragma once

#include "call_errno.hpp"
#include "env.hpp"
#include "flat_macro.hpp"
#include "str.hpp"

#include <filesystem>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

std::vector<std::pair<std::string, std::function<void()>>> &rebootping_tests();
extern std::vector<std::string> rebootping_test_failures;

template <typename... arg_types> inline void rebootping_test_fail(arg_types &&...args) {
    auto s = str(args...);
    std::cout << "rebootping_test_fail " << s << std::endl;
    rebootping_test_failures.push_back(std::string{s});

    auto rebootping_failures_max = env("rebootping_test_failures_max", 10);
    if (std::cmp_greater_equal(rebootping_test_failures.size(), rebootping_failures_max)) {
        throw std::runtime_error(str("Too many test failures: ", rebootping_test_failures.size(), " last was ", s));
    }
}

#define rebootping_test_check(a, cmp, b, ...)                                                                                                                  \
    do {                                                                                                                                                       \
        auto lhs = a;                                                                                                                                          \
        auto rhs = b;                                                                                                                                          \
        if (!(lhs cmp rhs)) {                                                                                                                                  \
            rebootping_test_fail(#a, "=", lhs, " ", #b, "=", rhs __VA_OPT__(, ) __VA_ARGS__);                                                                  \
            dbg(lhs, rhs);                                                                                                                                     \
        }                                                                                                                                                      \
    } while (0)

#define TEST(suite_name, test_name)                                                                                                                            \
    void suite_name##_##test_name();                                                                                                                           \
    namespace {                                                                                                                                                \
    auto rebootping_test_register_##suite_name##_##test_name = rebootping_tests().emplace_back(#suite_name "_" #test_name, suite_name##_##test_name);          \
    }                                                                                                                                                          \
    void suite_name##_##test_name()

struct tmpdir {
    std::string tmpdir_name;

    inline tmpdir() {
        tmpdir_name = std::filesystem::temp_directory_path().string() + "/rebootping_test.XXXXXX";
        CALL_ERRNO_BAD_VALUE(mkdtemp, nullptr, tmpdir_name.data()); // can modify since C++11
    }

    inline ~tmpdir() {
        for (const auto &i : std::filesystem::recursive_directory_iterator(tmpdir_name)) {
            std::cout << "tmpdir " << (i.is_regular_file() ? i.file_size() : 0) << '\t' << i.path() << std::endl;
        }
        auto removed_count = std::filesystem::remove_all(tmpdir_name);
        std::cout << "tmpdir cleaned " << tmpdir_name << " " << removed_count << std::endl;
    }
};