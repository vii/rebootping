#pragma once

#include "str.hpp"

#include <vector>
#include <functional>
#include <string>
#include <iostream>

std::vector<std::pair<std::string, std::function<void()>>>& rebootping_tests();
extern std::vector<std::string> rebootping_test_failures;

template<typename... arg_types>
void rebootping_test_fail(arg_types &&...args) {
    auto s = str(args...);
    std::cout << "rebootping_test_fail " << s << std::endl;
    rebootping_test_failures.push_back(std::string{s});
}

#define TEST(suite_name, test_name)                                                                                                                     \
    void suite_name##_##test_name();                                                                                                                    \
    namespace {                                                                                                                                         \
        auto rebootping_test_register_##suite_name##_##test_name = rebootping_tests().emplace_back(#suite_name "_" #test_name, suite_name##_##test_name); \
    }                                                                                                                                                   \
    void suite_name##_##test_name()
