#include "rebootping_event.hpp"

#include "rebootping_records_dir.hpp"

locked_reference<rebootping_event> &rebootping_event_log() {
    static locked_holder<rebootping_event> event_log{rebootping_records_dir()};
    return event_log;
}
void rebootping_event_log(std::string_view event_name, std::string_view event_message) {
    write_locked_reference(rebootping_event_log())->add_flat_record([&](auto &&record) {
        record.event_unixtime() = now_unixtime();
        record.event_name() = event_name;
        record.event_compilation_timestamp() = __DATE__ " " __TIME__;
        record.event_git_sha() = flat_git_sha_string;
        record.event_git_unixtime() = flat_git_unixtime;
        record.event_message() = event_message;

        flat_record_dump_as_json(std::cout, record);
        std::cout << std::endl;
    });
}
