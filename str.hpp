#pragma once

#include <sstream>
#include <string>
#include <unordered_map>

template<typename... Args>
inline std::string str(Args &&... args) {
    std::ostringstream oss;
    (oss << ... << args);
    return oss.str();
}
template<typename key_type, typename value_type>
std::ostream &operator<<(std::ostream &os, std::unordered_map<key_type, value_type> const &h) {
    os << "{";
    bool first = true;
    for (auto const &[k, v] : h) {
        if (!first) os << ",";
        first = false;
        os << k << ":" << v;
    }
    return os << "}";
}