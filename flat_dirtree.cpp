#include "flat_dirtree.hpp"

#include <cstring>
#include <ctime>
#include <string_view>
#include <vector>

double string_to_unixtime(std::string_view s) {
    tm parsed;
    std::memset(&parsed, 0, sizeof(parsed));
    parsed.tm_year = std::stoi(std::string(s.substr(0, 4)));
    if (s.size() >= 6) {
        parsed.tm_mon = std::stoi(std::string(s.substr(4, 6)));
    }
    if (s.size() >= 8) {
        parsed.tm_mday = std::stoi(std::string(s.substr(6, 8)));
    }
    return timegm(&parsed);
}

std::vector<std::string> fetch_flat_timeshard_dirs(std::string_view flat_dir, std::string_view flat_dir_suffix) {
    std::vector<std::string> dirs;
    for (auto &p : std::filesystem::directory_iterator(flat_dir)) {
        if (std::filesystem::exists(p / std::filesystem::path{flat_dir_suffix})) {
            dirs.push_back(p.path().filename().string());
        }
    }
    std::sort(dirs.begin(), dirs.end());
    return dirs;
}
