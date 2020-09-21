#pragma once

#include <csignal>
#include <unistd.h>
#include <random>
#include <cmath>
#include <cstring>
#include <vector>
#include <utility>
#include <atomic>
#include <unordered_map>
#include <thread>
#include <iostream>
#include <pcap/pcap.h>
#include "str.hpp"
#include "file_contents_cache.hpp"
#include "event_tracker.hpp"
#include "now.hpp"
#include "limited_pcap_dumper.hpp"
#include "network_interfaces_manager.hpp"
#include "network_interface_watcher.hpp"

struct network_interfaces_manager {
    std::unordered_map<std::string, std::unique_ptr<network_interface_watcher> > watchers;
    ping_record_store ping_store;

    std::unordered_map<std::string, std::vector<sockaddr>> discover_known_ifs();
    void report_html();
};