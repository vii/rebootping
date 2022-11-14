#include "flat_mmap.hpp"

#include "thread_context.hpp"

namespace {
uint64_t round_up_to_aligned_page(uint64_t len) {
    auto pagesize = getpagesize();
    auto aligned_len = pagesize * ((len + pagesize - 1) / pagesize);
    return aligned_len;
}
} // namespace

flat_mmap::flat_mmap(std::string filename, flat_mmap_settings const &settings)
    : mmap_filename(std::move(filename)), mmap_fd(-1), mmap_base(nullptr), mmap_settings(settings), mmap_len(0) {
    open_mmap();
}

void flat_mmap::mmap_allocate_at_least(uint64_t len) {
    if (mmap_len >= len) return;
    auto aligned_len = round_up_to_aligned_page(len);
    CALL_ERRNO_MINUS_1(fallocate, mmap_fd, 0, mmap_len, aligned_len - mmap_len);

    mmap_ensure_mapped(aligned_len);
}

void flat_mmap::mmap_sparsely_allocate_at_least(uint64_t len) {
    if (mmap_len >= len) return;
    auto aligned_len = round_up_to_aligned_page(len);
    CALL_ERRNO_MINUS_1(ftruncate, mmap_fd, aligned_len);

    mmap_ensure_mapped(aligned_len);
}

void flat_mmap::mmap_ensure_mapped(uint64_t new_mmap_len) {
    if (new_mmap_len <= mmap_len) { return; }
    if (mmap_base) {
        mmap_base = CALL_ERRNO_BAD_VALUE(mremap, MAP_FAILED, mmap_base, mmap_len, new_mmap_len, MREMAP_MAYMOVE);
    } else {
        mmap_base =
            CALL_ERRNO_BAD_VALUE(mmap, MAP_FAILED, nullptr, new_mmap_len, PROT_READ | (mmap_settings.mmap_readonly ? 0 : PROT_WRITE), MAP_SHARED, mmap_fd, 0);
    }
    mmap_len = new_mmap_len;
}

void flat_mmap::open_mmap() {
    add_thread_context _("mmap_filename", mmap_filename);

    destroy_mmap();
    mmap_fd = CALL_ERRNO_MINUS_1(open, mmap_filename.c_str(), mmap_settings.mmap_readonly ? O_RDONLY : (O_CREAT | O_RDWR), 0666);
    struct stat buf;
    try {
        CALL_ERRNO_MINUS_1(fstat, mmap_fd, &buf);

        mmap_ensure_mapped(buf.st_size);
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
