#pragma once

#include "file_contents_cache.hpp"
#include "limited_pcap_dumper.hpp"
#include "network_flat_records.hpp"
#include "now_unixtime.hpp"
#include "str.hpp"
#include "wire_layout.hpp"
#include "locked_reference.hpp"
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

define_flat_record(ping_record,
                   (double, ping_start_unixtime),
                   (double, ping_sent_seconds),
                   (double, ping_recv_seconds),
                   (network_addr, ping_dest_addr),
                   (flat_bytes_interned_ptr, ping_interface),
                   (uint64_t, ping_cookie), );

locked_reference<ping_record> &ping_record_store();

define_flat_record(last_ping_record,
                   (double, ping_start_unixtime),
                   (uint64_t, ping_slot),
                   (flat_index_field<if_ip_lookup>, ping_if_ip_index), );
locked_reference<last_ping_record> &last_ping_record_store();


define_flat_record(unanswered_ping_record,
                   (double, ping_start_unixtime),
                   (uint64_t, ping_slot),
                   (flat_index_linked_field<if_ip_lookup>, ping_if_ip_index), );
locked_reference<unanswered_ping_record> &unanswered_ping_record_store();
