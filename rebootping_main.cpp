#include "call_errno.hpp"
#include "cmake_variables.hpp"
#include "file_contents_cache.hpp"
#include "flat_record.hpp"
#include "network_interfaces_manager.hpp"
#include "now_unixtime.hpp"
#include "ping_health_decider.hpp"
#include "ping_record_store.hpp"
#include "rebootping_records_dir.hpp"
#include "rebootping_report_html.hpp"
#include "str.hpp"
#include "wire_layout.hpp"
#include "rebootping_event.hpp"

#include <pcap/pcap.h>

#include <atomic>
#include <cmath>
#include <csignal>
#include <cstring>
#include <iostream>
#include <random>
#include <regex>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

int global_exit_value;

void signal_callback_handler(int signum) {
    global_exit_value = signum;
}




int main() {
    signal(SIGINT, signal_callback_handler);
    signal(SIGTERM, signal_callback_handler);

    network_interfaces_manager interfaces_manager;
    rebootping_event_log("rebootping_init");
    double last_dump_info_time = 0;
    double last_heartbeat = std::nan("");
    while (!global_exit_value) {
        auto known_ifs = interfaces_manager.discover_known_ifs();
        auto now = now_unixtime();
        if (env("ping_heartbeat_external_addresses", true)) {
            ping_external_addresses(known_ifs, now, last_heartbeat);
        }
        if (now > last_dump_info_time + env("dump_info_spacing_seconds", 60.0)) {
            report_html_dump();
            last_dump_info_time = now;
        }
        last_heartbeat = now;
        std::this_thread::sleep_for(std::chrono::duration<double>(env("ping_heartbeat_spacing_seconds", 1.0)));
    }
    rebootping_event_log("rebootping_exit", str("global_exit_value ", global_exit_value));
    return global_exit_value;
}
