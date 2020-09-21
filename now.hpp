#pragma once

#include <chrono>

inline double now_unixtime() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() / 1e9;
}
