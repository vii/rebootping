#include "flat_mmap.hpp"

flat_mmap::flat_mmap(std::string filename, flat_mmap_settings const &settings) : mmap_filename(std::move(filename)),
                                                                                 mmap_fd(-1),
                                                                                 mmap_base(nullptr),
                                                                                 mmap_settings(settings),
                                                                                 mmap_len(0) {
    open_mmap();
}

void flat_mmap::mmap_allocate_at_least(uint64_t len) {
    if (mmap_len >= len) return;
    auto pagesize = getpagesize();
    auto aligned_len = pagesize * ((len + pagesize - 1) / pagesize);
    CALL_ERRNO_MINUS_1(fallocate, mmap_fd, 0, mmap_len, aligned_len - mmap_len);

    if (mmap_base) {
        mmap_base = CALL_ERRNO_BAD_VALUE(mremap, MAP_FAILED,
                                         mmap_base, mmap_len, aligned_len, MREMAP_MAYMOVE);
    }
    mmap_len = aligned_len;
}

void flat_mmap::open_mmap() {
    destroy_mmap();
    mmap_fd = CALL_ERRNO_MINUS_1(open,
                                 mmap_filename.c_str(),
                                 mmap_settings.mmap_readonly ? O_RDONLY : (O_CREAT | O_RDWR),
                                 0666);
    struct stat buf;
    try {
        CALL_ERRNO_MINUS_1(fstat, mmap_fd, &buf);
        mmap_len = buf.st_size;
        mmap_allocate_at_least(getpagesize());

        mmap_base = CALL_ERRNO_BAD_VALUE(mmap, MAP_FAILED,
                                         nullptr, mmap_len, PROT_READ | (mmap_settings.mmap_readonly ? 0 : PROT_WRITE),
                                         MAP_SHARED, mmap_fd, 0);
    } catch (...) {
        destroy_mmap();
        throw;
    }
}

void flat_mmap::destroy_mmap() {
    if (mmap_base) {
        CALL_ERRNO_MINUS_1(munmap, mmap_base, mmap_len);
        mmap_base = nullptr;
        mmap_len = 0;
    }
    if (mmap_fd >= 0) {
        CALL_ERRNO_MINUS_1(close, mmap_fd);
        mmap_fd = -1;
    }
}
