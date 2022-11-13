#pragma once

#include "str.hpp"

#include <iostream>
#include <string>
#include <string_view>
#include <utility>

template<typename value_type>
struct escape_json_tag {
    value_type escape_value;
    template<typename constructor_type, std::enable_if_t<std::is_convertible<constructor_type, value_type>::value> * = nullptr>
    explicit escape_json_tag(constructor_type &&v) : escape_value(std::forward<constructor_type>(v)) {}
};

inline decltype(auto) escape_json(std::string_view value) {
    return escape_json_tag<std::string_view>(value);
}
inline decltype(auto) escape_json(std::string const &value) {
    return escape_json_tag<std::string_view>(value);
}
inline decltype(auto) escape_json(char const *value) {
    return escape_json_tag<std::string_view>(value);
}

inline decltype(auto) escape_json(int8_t c) {
    return (int) c;
}
inline decltype(auto) escape_json(uint8_t c) {
    return (int) c;
}
inline decltype(auto) escape_json(int32_t i) {
    return i;
}
inline decltype(auto) escape_json(uint32_t i) {
    return i;
}
inline decltype(auto) escape_json(uint64_t u) {
    return escape_json_tag<decltype(u)>(u);
}
inline decltype(auto) escape_json(int64_t i) {
    return escape_json_tag<decltype(i)>(i);
}
inline decltype(auto) escape_json(double d) {
    return escape_json_tag<double>(d);
}
inline decltype(auto) escape_json(float d) {
    return escape_json_tag<double>(d);
}

std::ostream &operator<<(std::ostream &os, escape_json_tag<std::string_view> s);
std::ostream &operator<<(std::ostream &os, escape_json_tag<double> s);

template<typename int_type, std::enable_if_t<std::is_integral_v<int_type>> * = nullptr>
inline std::ostream &operator<<(std::ostream &os, escape_json_tag<int_type> i) {
    auto val = i.escape_value;

    if (std::cmp_less_equal(val, (uint64_t(1) << 53) - 1) && std::cmp_greater_equal(val, -((int64_t(1) << 53) - 1))) {
        os << val;
    } else {
        os << '"' << val << '"';
    }
    return os;
}
std::string escape_html_string(std::string const &s);

template<typename input_type>
inline std::string escape_html(input_type &&in) {
    return escape_html_string(str(in));
}
