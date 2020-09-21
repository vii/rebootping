#pragma once

#include "limited_pcap_dumper.hpp"
#include "now.hpp"
#include "event_tracker.hpp"
#include "file_contents_cache.hpp"
#include "str.hpp"
#include "wire_layout.hpp"

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

struct rebootping_icmp_payload {
    uint64_t rebootping_slot;
    uint64_t rebootping_cookie;
}__attribute__ ((__packed__));

struct rebootping_icmp_packet {
    icmp_header packet_icmp;
    rebootping_icmp_payload packet_payload;
}__attribute__ ((__packed__));

struct rebootping_ether_packet {
    ether_header packet_ether;
    ip_header packet_ip;
    rebootping_icmp_packet packet;
}__attribute__ ((__packed__));

struct ping_record {
    double ping_start_unixtime = now_unixtime();
    double ping_sent_unixtime = std::nan("");
    double ping_recv_unixtime = std::nan("");
    sockaddr ping_dest_addr;
    std::string ping_interface;
    uint64_t ping_cookie;

    ping_record();
};

struct ping_record_store {
    std::vector<ping_record> ping_records{64 * 1024};
    std::atomic<size_t> ping_next_record = 0;

    ping_record *process_one_icmp_packet(const struct pcap_pkthdr *h, const u_char *bytes);

    size_t add_ping_record(ping_record &&record);

    event_tracker_contents track_ping(std::string const &ping_type, ping_record const &record);
};
