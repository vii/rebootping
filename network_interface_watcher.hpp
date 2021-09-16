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

struct network_interface_watcher {
    std::string interface_name;
    explicit network_interface_watcher(std::string_view name):interface_name(name){}
    void learn_from_packet(const struct pcap_pkthdr* h, const u_char*bytes);

    static void learn_from_pcap_file(std::string const& filename);

    network_interface_watcher(network_interface_watcher const &) = delete;

    network_interface_watcher(network_interface_watcher &&) = delete;

    network_interface_watcher &operator=(network_interface_watcher const &) = delete;

    network_interface_watcher &operator=(network_interface_watcher &&) = delete;
};

struct network_interface_watcher_live : network_interface_watcher {
    pcap_t *interface_pcap = nullptr;
    std::mutex watcher_mutex;
    std::atomic<bool> interface_should_stop = false;
    std::atomic<bool> interface_has_stopped = false;
    std::thread interface_thread;
    std::unordered_map<macaddr, std::unique_ptr<limited_pcap_dumper>> interface_dumpers;

    explicit network_interface_watcher_live(std::string_view name);

    void run_watcher_loop();

    void open_and_process_packets();

    limited_pcap_dumper &dumper_for_macaddr(macaddr const &ma);

    limited_pcap_dumper *existing_dumper_for_macaddr(macaddr const &ma);

    void process_one_packet(const struct pcap_pkthdr *h, const u_char *bytes);
    ~network_interface_watcher_live();
};

