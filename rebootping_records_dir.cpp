#include "rebootping_records_dir.hpp"
#include "env.hpp"

#include <filesystem>
#include <string>

std::string rebootping_records_dir() {
    auto dir = env("rebootping_records_dir", "rebootping_records_dir/");
    std::filesystem::create_directories(dir);
    return dir;
}
