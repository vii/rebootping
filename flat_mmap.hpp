#pragma once

#include "call_errno.hpp"

#include <sys/mman.h>
#include <sys/stat.h>

#include <cassert>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <cstdint>

struct flat_mmap_settings {
    bool mmap_readonly = false;
};

class flat_mmap {
    const std::string mmap_filename;
    int mmap_fd;
    void *mmap_base;
    flat_mmap_settings mmap_settings;
    uint64_t mmap_len;

  public:
    explicit flat_mmap(std::string filename, flat_mmap_settings const &settings = flat_mmap_settings());

    flat_mmap(flat_mmap const &other) = delete;
    flat_mmap &operator=(flat_mmap const &other) = delete;

    flat_mmap(flat_mmap &&other) = default;

    void mmap_allocate_at_least(uint64_t len);
    void mmap_sparsely_allocate_at_least(uint64_t len);

    [[nodiscard]] std::string_view flat_mmap_filename() const { return mmap_filename; }

    [[nodiscard]] uint64_t mmap_allocated_len() const { return mmap_len; }

    template <typename T> inline T &mmap_cast(uint64_t off, uint64_t count = 1) const {
        assert(off <= mmap_len);
        assert(off + sizeof(T) * count <= mmap_len);
        assert(off + sizeof(T) * count >= off);

        return *reinterpret_cast<T *>(static_cast<unsigned char *>(mmap_base) + off);
    }

    inline ~flat_mmap() { destroy_mmap(); }

  private:
    void open_mmap();

    void destroy_mmap();

    void mmap_ensure_mapped(uint64_t new_mmap_len);
};
