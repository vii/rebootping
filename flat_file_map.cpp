#include "flat_file_map.hpp"

flat_file_map::flat_file_map(std::string filename, bool readonly) :
        mmap_filename(std::move(filename)),
        mmap_fd(-1),
        mmap_base(nullptr),
        mmap_readonly(readonly),
        mmap_len(0) {
    open_mmap();
}

void flat_file_map::mmap_allocate_at_least(off_t len) {
    if (mmap_len >= len)return;
    auto pagesize = getpagesize();
    auto aligned_len = pagesize * ((len + pagesize - 1) / pagesize);
    CALL_ERRNO_MINUS_1(fallocate, mmap_fd, 0, mmap_len, aligned_len - mmap_len);

    if (mmap_base) {
        mmap_base = CALL_ERRNO_BAD_VALUE(mremap, MAP_FAILED,
                                         mmap_base, mmap_len, aligned_len, MREMAP_MAYMOVE);
    }
    mmap_len = aligned_len;
}

void flat_file_map::open_mmap() {
    destroy_mmap();
    mmap_fd = CALL_ERRNO_MINUS_1(open,
                                 mmap_filename.c_str(),
                                 mmap_readonly ? O_RDONLY : O_CREAT | O_RDWR);
    struct stat buf;
    try {
        CALL_ERRNO_MINUS_1(fstat, mmap_fd, &buf);
        mmap_len = buf.st_size;
        mmap_allocate_at_least(getpagesize());

        mmap_base = CALL_ERRNO_BAD_VALUE(mmap, MAP_FAILED,
                                         nullptr, mmap_len, PROT_READ | (mmap_readonly ? 0 : PROT_WRITE),
                                         MAP_SHARED, mmap_fd, 0);
    } catch (...) {
        destroy_mmap();
        throw;
    }

}

void flat_file_map::destroy_mmap() {
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
