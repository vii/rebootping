#pragma once

#include "event_tracker.hpp"
#include "file_contents_cache.hpp"
#include "limited_pcap_dumper.hpp"
#include "now_unixtime.hpp"
#include "ping_record_store.hpp"
#include "str.hpp"
#include "wire_layout.hpp"

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
#include "loop_thread.hpp"

void network_interface_watcher_learn_from_pcap_file(std::string const &filename);
std::unique_ptr<loop_thread> network_interface_watcher_thread(std::string interface_name);

