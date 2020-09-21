#pragma once

#include <string>

// return true if changed
bool file_contents_cache_write(std::string const &filename, std::string const &contents);
