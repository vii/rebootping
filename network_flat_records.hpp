#pragma once

#include "flat_bytes_field.hpp"
#include "flat_hash.hpp"
#include "flat_index_field.hpp"
#include "flat_mfu_mru.hpp"
#include "flat_record.hpp"
#include "wire_layout.hpp"

using network_addr = in_addr_t;

inline network_addr network_addr_from_sockaddr(sockaddr const&sa) {
    if (sa.sa_family != AF_INET) {
        throw std::runtime_error(str("network_addr_from_sockaddr cannot handle family ", sa.sa_family));
    }
    return reinterpret_cast<sockaddr_in const*>(&sa)->sin_addr.s_addr;
}

inline network_addr network_addr_from_string(const std::string& addr) {
    auto sa = sockaddr_from_string(addr, AF_INET);
    return network_addr_from_sockaddr(sa);
}
inline sockaddr sockaddr_from_network_addr(network_addr na) {
    sockaddr ret;
    std::memset(&ret,0,sizeof(ret));
    ret.sa_family = AF_INET;
    reinterpret_cast<sockaddr_in*>(&ret)->sin_addr.s_addr = na;
    return ret;
}


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

struct if_ip_lookup {
    flat_bytes_interned_tag lookup_if;
    network_addr lookup_addr;

    inline bool operator==(if_ip_lookup const &other) const {
        return lookup_if.bytes_offset == other.lookup_if.bytes_offset && lookup_addr == other.lookup_addr;
    }
};
template<>
inline uint64_t flat_hash_function(if_ip_lookup const &k) {
    return flat_hash_function(k.lookup_addr) ^ flat_hash_function(k.lookup_if.bytes_offset);
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
                   (flat_bytes_interned_ptr, ping_interface),
                   (uint64_t, ping_cookie), );

ping_record &ping_record_store();

define_flat_record(last_ping_record,
                   (double, ping_start_unixtime),
                   (uint64_t, ping_slot),
                   (flat_index_field<if_ip_lookup>, ping_if_index), );
last_ping_record &last_ping_record_store();

define_flat_record(interface_health_record,
                   (double, health_decision_unixtime),
                   (double, health_last_good_unixtime),
                   (double, health_last_bad_unixtime),
                   (double, health_last_active_unixtime),
                   (flat_bytes_interned_ptr, health_interface),
                   (flat_index_linked_field<flat_bytes_interned_ptr>, health_interface_index), );