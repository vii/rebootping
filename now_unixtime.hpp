#pragma once
#include "str.hpp"

#include <chrono>
#include <ctime>

inline double now_unixtime() { return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count() / 1e9; }
inline std::string yyyymmdd(double unixtime) {
    char buffer[9];
    std::time_t rounded_time = unixtime;
    std::tm ti;
    if (!gmtime_r(&rounded_time, &ti)) { throw std::runtime_error(str("yyyymmdd gmtime_r failed: ", unixtime)); }
    if (strftime(buffer, sizeof(buffer), "%Y%m%d", &ti) != sizeof(buffer) - 1) { throw std::runtime_error(str("yyyymmdd strftime failed: ", unixtime)); }
    return std::string(buffer, sizeof(buffer) - 1);
}
