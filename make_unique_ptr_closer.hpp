#pragma once

#include <memory>

template<typename T, typename Deleter>
inline std::unique_ptr<T, Deleter> make_unique_ptr_closer(T *type, Deleter deleter) {
    return std::unique_ptr<T, Deleter>(type, deleter);
}
