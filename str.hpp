#pragma once

#include <sstream>
#include <string>

template<typename... Args>
inline std::string str(Args &&...args) {
    std::ostringstream oss;
    (oss << ... << args);
    return oss.str();
}
