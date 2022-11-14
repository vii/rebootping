#include "space_estimate_for_path.hpp"

#include <mutex>
#include <unordered_map>

std::uintmax_t space_estimate_for_path(const std::filesystem::path &p, std::uintmax_t space_to_remove) {
    static std::mutex mutex;
    static std::unordered_map<std::string, std::uintmax_t> space_estimates;
    auto str_path = p;
    std::lock_guard _(mutex);
    auto i = space_estimates.find(str_path);
    if (i == space_estimates.end()) { i = space_estimates.insert(std::make_pair(str_path, std::filesystem::space(p.parent_path()).available)).first; }
    if (i->second >= space_to_remove) { i->second -= space_to_remove; }
    return i->second;
}
