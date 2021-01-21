#pragma once

#include "event_tracker.hpp"
#include "file_contents_cache.hpp"
#include "limited_pcap_dumper.hpp"
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
    uint64_t rebootping_slot;
    uint64_t rebootping_cookie;
} __attribute__((__packed__));

struct rebootping_ether_packet : wire_header<
                                         ether_header,
                                         ip_header,
                                         icmp_header,
                                         rebootping_icmp_payload> {
};

struct rebootping_icmp_packet : wire_header<icmp_header, rebootping_icmp_payload> {
};

struct ping_record {
    double ping_start_unixtime = now_unixtime();
    double ping_sent_unixtime = std::nan("");
    double ping_recv_unixtime = std::nan("");
    sockaddr ping_dest_addr;
    std::string ping_interface;
    uint64_t ping_cookie;

    ping_record();
};

#include "flat_timeshard.hpp"

/*
define_flat_timeshard(ping_record,
                      (double,ping_start_unixtime),
                      (double,ping_sent_unixtime),
                      (double,ping_recv_unixtime),
                      (sockaddr,ping_dest_addr),
                      (flat_bytes,ping_interface),
                      (uint64_t,ping_cookie)
                      );
*/
struct ping_record_store {
    std::vector<ping_record> ping_records{64 * 1024};
    std::atomic<size_t> ping_next_record = 0;

    ping_record *process_one_icmp_packet(const struct pcap_pkthdr *h, const u_char *bytes);

    size_t add_ping_record(ping_record &&record);

    event_tracker_contents track_ping(std::string const &ping_type, ping_record const &record);
};
