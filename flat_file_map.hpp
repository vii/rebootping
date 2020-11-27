#pragma once

#include "call_errno.hpp"
#include <string>
#include <utility>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cassert>



class flat_file_map {
    const std::string mmap_filename;
    int mmap_fd;
    void *mmap_base;
    bool mmap_readonly;
    off_t mmap_len;

public:
    flat_file_map(std::string filename, bool readonly);

    flat_file_map(flat_file_map const &other) = delete;

    flat_file_map(flat_file_map &&other) = default;


    void mmap_allocate_at_least(off_t len);

    template<typename T>
    inline T &mmap_cast(off_t off, off_t count=1) {
        assert(off <= mmap_len);
        assert(off + sizeof(T)*count <= mmap_len);
        assert(off + sizeof(T)*count >= off);

        return *static_cast<T *>(static_cast<unsigned char *>(mmap_base) + off);
    }

    inline ~flat_file_map() {
        destroy_mmap();
    }

private:

    void open_mmap();

    void destroy_mmap();

};


