#pragma once

#include <string_view>
#include <unordered_map>

extern thread_local std::unordered_map<std::string_view, std::string_view> thread_context;

struct add_thread_context {
    std::string_view thread_context_key;
    std::string_view thread_context_previous;

    inline add_thread_context(std::string_view key, std::string_view value) : thread_context_key(key), thread_context_previous(thread_context[key]) {
        set_thread_context_value(value);
    }
    inline ~add_thread_context() {
        set_thread_context_value(thread_context_previous);
    }

private:
    inline void set_thread_context_value(std::string_view value) {
        if (value.empty()) {
            thread_context.erase(thread_context_key);
        } else {
            thread_context[thread_context_key] = value;
        }
    }
};