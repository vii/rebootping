#pragma once

#include "flat_bytes_field.hpp"
#include "flat_hash.hpp"
#include "flat_index_field.hpp"
#include "flat_mfu_mru.hpp"
#include "flat_record.hpp"
#include "wire_layout.hpp"

using network_addr = in_addr_t;

inline network_addr network_addr_from_sockaddr(sockaddr const &sa) {
    if (sa.sa_family != AF_INET) {
        throw std::runtime_error(str("network_addr_from_sockaddr cannot handle family ", sa.sa_family));
    }
    return reinterpret_cast<sockaddr_in const *>(&sa)->sin_addr.s_addr;
}

inline network_addr network_addr_from_string(const std::string &addr) {
    auto sa = sockaddr_from_string(addr, AF_INET);
    return network_addr_from_sockaddr(sa);
}
inline sockaddr sockaddr_from_network_addr(network_addr na) {
    sockaddr ret;
    std::memset(&ret, 0, sizeof(ret));
    ret.sa_family = AF_INET;
    reinterpret_cast<sockaddr_in *>(&ret)->sin_addr.s_addr = na;
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

template<typename addr>
struct if_addr_lookup {
    flat_bytes_interned_tag lookup_if = flat_bytes_interned_tag{0};
    addr lookup_addr;

    inline bool operator==(if_addr_lookup<addr> const &other) const {
        return lookup_if.bytes_offset == other.lookup_if.bytes_offset && lookup_addr == other.lookup_addr;
    }
};
template<typename if_addr_lookup_addr>
concept if_addr_lookup_concept = requires(if_addr_lookup_addr a) {
    { a.lookup_if }
    ->std::same_as<flat_bytes_interned_tag>;
    {a.lookup_addr};
};

template<typename addr>
inline uint64_t flat_hash_function(if_addr_lookup<addr> const &k) {
    return flat_hash_function(k.lookup_addr) ^ flat_hash_function(k.lookup_if.bytes_offset);
}

template<typename addr>
decltype(auto) flat_timeshard_field_compare_prepare_key(if_addr_lookup<addr> *) {
    return [](flat_timeshard &comparer_timeshard, auto &&input) {
        if constexpr (std::is_constructible_v<if_addr_lookup<addr>, decltype(input)>) {
            return input;
        } else {
            return if_addr_lookup<addr>{
                    comparer_timeshard.smap_store_string(input.first),
                    input.second};
        }
    };
}
template<typename addr>
decltype(auto) flat_timeshard_field_compare_prepare_key_maybe(if_addr_lookup<addr> *) {
    return [](flat_timeshard &comparer_timeshard, auto &&input) -> std::optional<if_addr_lookup<addr>> {
        if constexpr (std::is_constructible_v<if_addr_lookup<addr>, decltype(input)>) {
            return input;
        } else {
            auto s = comparer_timeshard.timeshard_lookup_interned_string(input.first);
            if (!s) {
                return std::nullopt;
            }
            return if_addr_lookup<addr>{s.value(), input.second};
        }
    };
}

template<typename addr>
inline bool flat_hash_compare(
        flat_timeshard_field_comparer const &comparer, if_addr_lookup<addr> const &lhs, if_addr_lookup<addr> const &rhs) {
    return flat_hash_compare(comparer, lhs.lookup_if, rhs.lookup_if) && flat_hash_compare(comparer, lhs.lookup_addr, rhs.lookup_addr);
}


using if_ip_lookup = if_addr_lookup<network_addr>;
using if_mac_lookup = if_addr_lookup<macaddr>;

namespace std {
    template<>
    struct hash<if_ip_lookup> {
        inline size_t operator()(if_ip_lookup const &a) const {
            return flat_hash_function(a);
        }
    };

    template<>
    struct hash<if_mac_lookup> {
        inline size_t operator()(if_mac_lookup const &a) const {
            return flat_hash_function(a);
        }
    };
}// namespace std


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
                   (flat_index_field<if_mac_lookup>, arp_macaddr_index));

arp_response_record &arp_response_record_store();
