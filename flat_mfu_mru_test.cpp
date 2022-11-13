#include "flat_mfu_mru.hpp"
#include "rebootping_test.hpp"
#include <algorithm>
#include <random>
#include <string>

TEST(flat_mfu_mru_test_suite, empty) {
    flat_mfu_mru<std::string, 10, 5> fmms;
    rebootping_test_check(fmms.known_keys_and_counts().size(), ==, 0);
    flat_mfu_mru<uint64_t, 1, 10> fmmu;
    rebootping_test_check(fmmu.known_keys_and_counts().size(), ==, 0);
}

TEST(flat_mfu_mru_test_suite, just_one) {
    flat_mfu_mru<std::string, 10, 5> fmms;
    fmms.notice_key("hello");
    rebootping_test_check(fmms.known_keys_and_counts().size(), ==, 1);
    rebootping_test_check(fmms.known_keys_and_counts()["hello"], ==, 1);
    flat_mfu_mru<uint64_t, 1, 10> fmmu;
    fmmu.notice_key(1331);
    rebootping_test_check(fmmu.known_keys_and_counts().size(), ==, 1);
    rebootping_test_check(fmmu.known_keys_and_counts()[1331], ==, 1);
}

TEST(flat_mfu_mru_test_suite, small_shuffle) {
    for (int i = 0; 10000 > i; ++i) {
        std::array<int, 10> a = {1, 2, 3, 1, 2, 3, 1, 2, 3, 4};
        std::shuffle(a.begin(), a.end(), std::default_random_engine(i));
        flat_mfu_mru<int, 3, 2> fmm;
        for (auto j : a) {
            fmm.notice_key(j);
        }
        rebootping_test_check(fmm.known_keys_and_counts()[1], ==, 3);
        rebootping_test_check(fmm.known_keys_and_counts()[2], ==, 3);
        rebootping_test_check(fmm.known_keys_and_counts()[3], ==, 3);
        rebootping_test_check(fmm.known_keys_and_counts()[4], ==, 1);
    }
}

TEST(flat_mfu_mru_test_suit, more_and_more) {
    flat_mfu_mru<int, 3, 1> fmm;

    for (int i = 0; 10000 > i; ++i) {
        for (int j = 0; i > j; ++j) {
            fmm.notice_key(i);
        }
    }
    rebootping_test_check(fmm.known_keys_and_counts()[9999], ==, 9999);
    rebootping_test_check(fmm.known_keys_and_counts()[9998], ==, 9998);
    rebootping_test_check(fmm.known_keys_and_counts()[9997], ==, 9997);
}

TEST(flat_mfu_mru_test_suit, more_and_more_noise) {
    flat_mfu_mru<int, 3, 2> fmm;
    int noise = 197878;

    for (int i = 0; 10000 > i; ++i) {
        for (int j = 0; i > j; ++j) {
            fmm.notice_key(i);
            fmm.notice_key(noise + i);
        }
    }
    rebootping_test_check(fmm.known_keys_and_counts()[9999], ==, 9999);
    rebootping_test_check(fmm.known_keys_and_counts()[9998], ==, 9998);
    rebootping_test_check(fmm.known_keys_and_counts()[9997], ==, 9997);
}