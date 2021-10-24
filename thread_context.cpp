#include "thread_context.hpp"

thread_local std::unordered_map<std::string_view, std::string_view> thread_context = {};