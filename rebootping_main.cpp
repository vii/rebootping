#include "flat_metrics.hpp"
#include "network_interfaces_manager.hpp"
#include "now_unixtime.hpp"
#include "ping_health_decider.hpp"
#include "rebootping_event.hpp"
#include "rebootping_report_html.hpp"
#include "str.hpp"

#include <sys/resource.h>

#include <cmath>
#include <csignal>
#include <iostream>
#include <thread>
#include <utility>

int global_exit_value;

void signal_callback_handler(int signum) { global_exit_value = signum; }

namespace {
void unlimit_open_files() {
    struct rlimit limits;
    CALL_ERRNO_MINUS_1(getrlimit, RLIMIT_NOFILE, &limits);
    if (limits.rlim_cur < limits.rlim_max) { std::cerr << "increasing RLIMIT_NOFILE from " << limits.rlim_cur << " to " << limits.rlim_max << std::endl; }
    limits.rlim_cur = limits.rlim_max;
    CALL_ERRNO_MINUS_1(setrlimit, RLIMIT_NOFILE, &limits);
    flat_metric().open_files_limit = limits.rlim_cur;
}
} // namespace

int main_actions() {
    CALL_ERRNO_BAD_VALUE(signal, SIG_ERR, SIGINT, signal_callback_handler);
    CALL_ERRNO_BAD_VALUE(signal, SIG_ERR, SIGTERM, signal_callback_handler);

    network_interfaces_manager interfaces_manager;
    flat_metrics_struct last_metric = flat_metric();
    ++flat_metric().metric_restarts;
    double last_dump_info_time = 0;
    double last_heartbeat = std::nan("");
    unlimit_open_files();

    while (!global_exit_value) {
        auto known_ifs = interfaces_manager.discover_known_ifs();
        if (interfaces_manager.has_nothing_to_manage()) {
            std::cerr << "rebootping_main not monitoring any interfaces" << std::endl;
            break;
        }
        auto now = now_unixtime();
        if (env("ping_heartbeat_external_addresses", true)) { ping_external_addresses(known_ifs, now, last_heartbeat); }
        if (now > last_dump_info_time + env("dump_info_spacing_seconds", 60.0)) {
            report_html_dump();
            last_dump_info_time = now;
            flat_metrics_struct current_metric = flat_metric();
            flat_metrics_report_delta(std::cout, current_metric, last_metric);
            last_metric = std::move(current_metric);
        }
        last_heartbeat = now;
        std::this_thread::sleep_for(std::chrono::duration<double>(env("ping_heartbeat_spacing_seconds", 1.0)));
    }
    rebootping_event_log("rebootping_exit", str("global_exit_value ", global_exit_value));
    report_html_dump();
    return global_exit_value;
}

int main() {
    int exit_value = 7;
    rebootping_event_log("rebootping_init");
    try {
        exit_value = main_actions();
    } catch (const std::exception &e) {
        rebootping_event_log("rebootping_exception", e.what());
        exit_value = 11;
    }
    rebootping_event_log("rebootping_exit", str("global_exit_value ", exit_value));
    return exit_value;
}