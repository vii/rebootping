#pragma once

#include <cstdlib>
#include <sstream>
#include <vector>

template<typename T>
inline T env_convert_default(T &&default_value, char const *given) {
    T ret;
    auto is = std::istringstream{given};
    is >> ret;
    if (!is.good()) {
        return default_value;
    }
    return ret;
}

template<>
inline std::string env_convert_default(std::string &&default_value, char const *given) {
    return given;
}

template<typename T>
inline T env(char const *var, T default_value) {
    auto given = std::getenv(var);
    if (!given) {
        return default_value;
    }
    return env_convert_default(std::move(default_value), given);
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
