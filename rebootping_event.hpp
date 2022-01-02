#pragma once

#include "flat_record.hpp"

define_flat_record(rebootping_event,
                   (double, event_unixtime),
                   (std::string_view, event_name),
                   (std::string_view, event_compilation_timestamp),
                   (std::string_view, event_git_sha), (double, event_git_unixtime), (std::string_view, event_message));

rebootping_event &rebootping_event_log();
void rebootping_event_log(std::string_view event_name, std::string_view event_message = "");
