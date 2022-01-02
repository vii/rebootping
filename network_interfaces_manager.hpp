#pragma once

#include "event_tracker.hpp"
#include "file_contents_cache.hpp"
#include "limited_pcap_dumper.hpp"
#include "network_interface_watcher.hpp"
#include "network_interfaces_manager.hpp"
#include "now_unixtime.hpp"
#include "str.hpp"
#include <atomic>
#include <cmath>
#include <csignal>
#include <cstring>
#include <iostream>
#include <pcap/pcap.h>
#include <random>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

struct network_interfaces_manager {
    std::unordered_map<std::string, std::unique_ptr<network_interface_watcher_live>> watchers;

    std::unordered_map<std::string, std::vector<sockaddr>> discover_known_ifs();

    void report_html_dumper(std::ostream &out);
};