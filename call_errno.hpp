#pragma once

#include "thread_context.hpp"

#include <cerrno>
#include <cstring>
#include <sstream>
#include <string>

struct errno_exception : public std::exception {
    errno_exception(int err, const std::string &syscall) : caught_errno(err) {
        std::ostringstream oss;
        oss << syscall << " " << std::strerror(err);
        for (auto &[k, v] : thread_context) { oss << std::endl << k << "=" << v << std::endl; }
        message = oss.str();
    }

    int caught_errno;
    std::string message;

    [[nodiscard]] const char *what() const noexcept override { return message.c_str(); }
};

#define CALL_ERRNO_BAD_VALUE(name, bad_value, ...) call_errno_bad_value([&] { return name(__VA_ARGS__); }, #name, bad_value)
#define CALL_ERRNO_MINUS_1(name, ...) CALL_ERRNO_BAD_VALUE(name, -1, __VA_ARGS__)

template <typename Function> inline auto call_errno_bad_value(Function const &f, char const *name, decltype(f()) bad_value) -> decltype(f()) {
    auto ret = f();
    if (ret == bad_value) { throw errno_exception(errno, name); }
    return ret;
}