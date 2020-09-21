#pragma once

#include <filesystem>

std::uintmax_t space_estimate_for_path(std::filesystem::path const &p, std::uintmax_t space_to_remove = 0);
