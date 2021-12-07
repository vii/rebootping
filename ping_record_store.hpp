#pragma once

#include "event_tracker.hpp"
#include "file_contents_cache.hpp"
#include "limited_pcap_dumper.hpp"
#include "network_flat_records.hpp"
#include "now_unixtime.hpp"
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

struct rebootping_icmp_payload {
    uint64_t ping_slot;
    uint64_t ping_cookie;
    double ping_start_unixtime;
} __attribute__((__packed__));

struct rebootping_ether_packet : wire_header<
                                         ether_header,
                                         ip_header,
                                         icmp_header,
                                         rebootping_icmp_payload> {
};

struct rebootping_icmp_packet : wire_header<icmp_header, rebootping_icmp_payload> {
};
void ping_record_store_prepare(sockaddr const &src_addr, sockaddr const &dst_addr, std::string_view ping_if, rebootping_icmp_payload &ping_payload);
void ping_record_store_process_one_icmp_packet(const struct pcap_pkthdr *h, const u_char *bytes);
