#pragma once

#include "limited_pcap_dumper.hpp"
#include "now.hpp"
#include "event_tracker.hpp"
#include "file_contents_cache.hpp"
#include "str.hpp"
#include "wire_layout.hpp"
#include "ping_record_store.hpp"

#include <pcap/pcap.h>

#include <iostream>
#include <thread>
#include <unordered_map>
#include <atomic>
#include <utility>
#include <vector>
#include <cstring>
#include <cmath>
#include <random>
#include <unistd.h>
#include <csignal>

struct network_interface_watcher {
    pcap_t *interface_pcap = nullptr;
    std::mutex watcher_mutex;
    std::atomic<bool> interface_should_stop = false;
    std::atomic<bool> interface_has_stopped = false;
    std::string interface_name;
    std::thread interface_thread;
    std::unordered_map<macaddr, std::unique_ptr<limited_pcap_dumper>> interface_dumpers;
    ping_record_store &ping_store;

    explicit network_interface_watcher(std::string name, ping_record_store &store);

    void run_watcher_loop();

    void open_and_process_packets();

    limited_pcap_dumper &dumper_for_macaddr(macaddr const &ma);
    limited_pcap_dumper *existing_dumper_for_macaddr(macaddr const& ma);

    void process_one_packet(const struct pcap_pkthdr *h, const u_char *bytes);

    ~network_interface_watcher();


    network_interface_watcher(network_interface_watcher const &) = delete;

    network_interface_watcher(network_interface_watcher &&) = delete;

    network_interface_watcher &operator=(network_interface_watcher const &) = delete;

    network_interface_watcher &operator=(network_interface_watcher &&) = delete;
};
