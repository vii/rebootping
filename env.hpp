#pragma once

#include <cstdlib>
#include <sstream>
#include <vector>

template<typename T>
inline T env(char const *var, T default_value) {
    auto given = std::getenv(var);
    if (!given) {
        return default_value;
    }
    T ret;
    auto is = std::istringstream{given};
    is >> ret;
    if (!is.good()) {
        return default_value;
    }
    return ret;
}

inline std::string env(char const *var, char const *default_value) {
    return env(var, std::string(default_value));
}

template<typename T>
inline std::vector<T> env(char const *var, std::vector<T> const &default_value) {
    auto given = std::getenv(var);
    if (!given) {
        return default_value;
    }
    std::vector<T> ret;
    auto is = std::istringstream{given};
    for (;;) {
        T tmp;
        is >> tmp;
        if (!is.good()) {
            break;
        }
        ret.push_back(tmp);
    }
    return ret;
}
