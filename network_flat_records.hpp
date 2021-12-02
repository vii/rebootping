#pragma once

#include "flat_bytes_field.hpp"
#include "flat_hash.hpp"
#include "flat_index_field.hpp"
#include "flat_mfu_mru.hpp"
#include "flat_record.hpp"
#include "wire_layout.hpp"

using network_addr = in_addr_t;

struct macaddr_ip_lookup {
    macaddr lookup_macaddr;
    network_addr lookup_addr;

    bool operator==(macaddr_ip_lookup const &) const = default;
};

template<>
inline uint64_t flat_hash_function(macaddr_ip_lookup const &k) {
    return flat_hash_function(k.lookup_addr) ^ flat_hash_function(k.lookup_macaddr.as_number());
}
template<>
inline uint64_t flat_hash_function(macaddr const &k) {
    return flat_hash_function(k.as_number());
}

define_flat_record(dns_response_record,
                   (double, dns_response_unixtime),
                   (std::string_view, dns_response_hostname),
                   (network_addr, dns_response_addr),
                   (flat_index_linked_field<macaddr_ip_lookup>, dns_macaddr_lookup_index));

dns_response_record &dns_response_record_store();

using network_port_collector = flat_mfu_mru<uint16_t, 10, 3>;

define_flat_record(tcp_accept_record,
                   (network_port_collector, tcp_ports),
                   (flat_index_field<macaddr>, tcp_macaddr_index));

tcp_accept_record &tcp_accept_record_store();

define_flat_record(udp_recv_record,
                   (network_port_collector, udp_ports),
                   (flat_index_field<macaddr>, udp_macaddr_index));

udp_recv_record &udp_recv_record_store();

using network_addr_collector = flat_mfu_mru<network_addr, 10, 3>;

define_flat_record(arp_response_record,
                   (network_addr_collector, arp_addresses),
                   (flat_index_field<macaddr>, arp_macaddr_index));

arp_response_record &arp_response_record_store();

define_flat_record(ping_record,
                   (double, ping_start_unixtime),
                   (double, ping_sent_seconds),
                   (double, ping_recv_seconds),
                   (network_addr, ping_dest_addr),
                   (std::string_view, ping_interface),
                   (uint64_t, ping_cookie), );

ping_record &ping_record_store();

define_flat_record(last_ping_record,
                   (double, ping_start_unixtime),
                   (uint64_t, ping_slot),
                   (flat_index_field<macaddr_ip_lookup>, ping_macaddr_index), );
last_ping_record &last_ping_record_store();

define_flat_record(interface_health_record,
                   (double, health_decision_unixtime),
                   (double, health_last_good_unixtime),
                   (double, health_last_bad_unixtime),
                   (double, health_last_active_unixtime),
                   (macaddr, health_interface_macaddr),
                   (flat_index_linked_field<macaddr_ip_lookup>, health_macaddr_index), );