#include "file_contents_cache.hpp"

#include <unordered_map>
#include <fstream>
#include <sstream>
#include <mutex>
#include <filesystem>


bool file_contents_cache_write(std::string const &filename, std::string const &contents) {
    static std::unordered_map<std::string, std::string> file_contents;
    static std::mutex mutex;
    std::lock_guard _{mutex};

    if (file_contents.find(filename) == file_contents.end()) {
        std::ifstream i{filename, std::ios::in | std::ios::binary};
        std::ostringstream current;
        current << i.rdbuf();
        file_contents[filename] = current.str();
    }
    if (contents == file_contents[filename]) {
        return false;
    }
    auto tmpfilename = filename + ".tmp";
    {
        std::ofstream o{tmpfilename, std::ios::out | std::ios::binary};
        o << contents;
    }
    std::filesystem::rename(tmpfilename, filename);
    file_contents[filename] = contents;
    return true;
}
