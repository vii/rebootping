#include "rebootping_test.hpp"
#include "rebootping_event.hpp"

TEST(rebootping_event_suite, event_log_test) {
    rebootping_event_log("test_event_name", "test_event_message");

    read_locked_reference log(rebootping_event_log());
    uint64_t count = 0;
    for (auto&& entry : log->timeshard_query()) {
        if (entry.event_name() == "test_event_name" && entry.event_message() == "test_event_message") {
            ++count;
        }
    }
    rebootping_test_check(count,>,0);
}
