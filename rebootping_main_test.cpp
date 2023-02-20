#include "rebootping_test.hpp"

TEST(rebootping_main_suite, rebootping_main_run_once) {
    setenv("watch_interface_name_regex", "impossible_interface_name", 1);
    int ret = system("./rebootping");
    rebootping_test_check(ret, ==, 0);
}