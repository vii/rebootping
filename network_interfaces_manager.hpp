#pragma once

#include "file_contents_cache.hpp"
#include "limited_pcap_dumper.hpp"
#include "loop_thread.hpp"
#include "network_interface_watcher.hpp"
#include "network_interfaces_manager.hpp"
#include "now_unixtime.hpp"
#include "str.hpp"

#include <pcap/pcap.h>

#include <atomic>
#include <cmath>
#include <csignal>
#include <cstring>
#include <iostream>
#include <random>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

struct network_interfaces_manager {
    std::unordered_map<std::string, std::unique_ptr<loop_thread>> watchers;

    std::unordered_map<std::string, std::vector<sockaddr>> discover_known_ifs();

    bool has_nothing_to_manage() const { return watchers.empty(); }
};