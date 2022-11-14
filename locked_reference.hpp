#pragma once

#include <mutex>
#include <shared_mutex>

template <typename T> struct read_locked_reference;
template <typename T> struct write_locked_reference;

template <typename T> struct locked_reference {
    locked_reference(T &t) : reference(t) {}
    friend struct read_locked_reference<T>;
    friend struct write_locked_reference<T>;

  private:
    std::shared_mutex reference_lock;
    T &reference;
};

template <typename T> struct locked_holder : locked_reference<T> {
    template <typename... Args> locked_holder(Args &&...args) : locked_reference<T>(held), held(std::forward<Args>(args)...) {}

  private:
    T held;
};

template <typename T> struct read_locked_reference {
    read_locked_reference(locked_reference<T> &ref) : lock(ref.reference_lock), reference(ref.reference) {}
    const T &operator*() const { return reference; }
    const T *operator->() const { return &reference; }

    std::shared_lock<std::shared_mutex> lock;
    const T &reference;
};

template <typename T> struct write_locked_reference {
    write_locked_reference(locked_reference<T> &ref) : lock(ref.reference_lock), reference(ref.reference) {}
    T &operator*() const { return reference; }
    T *operator->() const { return &reference; }

    std::unique_lock<std::shared_mutex> lock;
    T &reference;
};