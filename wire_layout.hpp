#pragma once

#include "str.hpp"

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

enum class ip_protocol : uint8_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
};

enum class icmp_type : uint8_t {
    ECHOREPLY = 0,
    ECHO = 8,
};

enum class ether_type : uint16_t {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
};
enum class tcp_flags : uint8_t {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PUSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
    ECNECHO = 0x40,
    CWR = 0x80,
};
enum class arp_operation : uint16_t {
    ARP_WHO_HAS = 1,
    ARP_REPLY = 2,
};

constexpr auto ETH_ALEN = 6;

struct macaddr {
    uint8_t mac_bytes[ETH_ALEN];

    [[nodiscard]] inline uint64_t as_number() const {
        uint64_t as_num = 0;
        for (auto c : mac_bytes) {
            as_num <<= 8;
            as_num += c;
        }
        return as_num;
    }

    inline uint32_t mac_manufacturer() const { return (uint32_t)(as_number() >> 24); }

    auto inline operator==(macaddr const &other) const { return as_number() == other.as_number(); }

    auto inline operator!=(macaddr const &other) const { return as_number() != other.as_number(); }
} __attribute__((__packed__));

inline std::ostream &operator<<(std::ostream &os, macaddr const &m) {
    const char *hex_digits = "0123456789abcdef";
    bool first = true;
    for (auto c : m.mac_bytes) {
        if (!first) { os << ":"; }
        os << hex_digits[c / 16] << hex_digits[c % 16];
        first = false;
    }
    return os;
}

namespace std {
template <> struct hash<macaddr> {
    inline size_t operator()(macaddr const &ma) const { return std::hash<uint64_t>()(ma.as_number()); }
};
} // namespace std

std::ostream &operator<<(std::ostream &os, in_addr const &i);

std::ostream &operator<<(std::ostream &os, sockaddr const &s);

struct ether_header {
    macaddr ether_dhost;
    macaddr ether_shost;
    u_int16_t ether_type_or_len;
} __attribute__((__packed__));

struct alignas(u_int16_t) ip_header {
    u_int8_t ip_vhl;
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
} __attribute__((__packed__));

struct alignas(u_int16_t) tcp_header {
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
    u_int8_t th_offx2;
    u_int8_t th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
} __attribute__((__packed__));

struct alignas(u_int16_t) icmp_header {
    u_int8_t icmp_type;
    u_int8_t icmp_code;
    u_int16_t icmp_cksum;
    union {
        u_int8_t ih_pptr;
        struct in_addr ih_gwaddr;
        struct ih_idseq {
            u_int16_t icd_id;
            u_int16_t icd_seq;
        } ih_idseq;
        uint32_t ih_void;
    } icmp_hun;
} __attribute__((__packed__));

struct alignas(u_int16_t) arp_header {
    u_int16_t arp_htype;
    u_int16_t arp_ptype;
    u_int8_t arp_hlen;
    u_int8_t arp_plen;
    u_int16_t arp_oper;
    macaddr arp_sender;
    in_addr arp_spa;
    macaddr arp_target;
    in_addr arp_tpa;
} __attribute__((__packed__));

struct alignas(u_int16_t) udp_header {
    u_int16_t uh_sport;
    u_int16_t uh_dport;
    u_int16_t uh_len;
    u_int16_t uh_sum;
} __attribute__((__packed__));

struct alignas(u_int16_t) dns_header {
    u_int16_t dns_id;
    u_int16_t dns_flags;
    u_int16_t dns_questions;
    u_int16_t dns_answers;
    u_int16_t dns_authorities;
    u_int16_t dns_additional;
} __attribute__((__packed__));

enum class dns_qtype : uint16_t {
    DNS_QTYPE_A = 1,
    DNS_QTYPE_NS = 2,
    DNS_QTYPE_CNAME = 5,
    DNS_QTYPE_MX = 0xf,
};

enum class dns_qclass : uint16_t {
    DNS_QCLASS_INET = 1,
};

enum class llc_lsap : uint8_t {
    LLC_LSAP_STP = 0x42,
};

enum class llc_ctrl : uint8_t {
    LLC_CTRL_STP = 3,
};

struct llc_stp_bpdu {
    llc_lsap llc_dsap;
    llc_lsap llc_ssap;
    llc_ctrl llc_control;
    uint16_t stp_protocol;
    uint8_t stp_version;
    uint8_t stp_message_type;
    uint8_t stp_flags;
    uint16_t stp_root;
    macaddr stp_root_macaddr;
    uint32_t stp_root_cost;
    uint16_t stp_bridge;
    macaddr stp_bridge_macaddr;
    // more fields skipped
};

template <typename... packet_types> struct wire_header : packet_types... {
    template <typename pointer> static wire_header<packet_types...> const *header_from_packet(pointer *bytes, size_t caplen) {
        if (sizeof(wire_header<packet_types...>) > caplen) { return nullptr; }
        return reinterpret_cast<wire_header<packet_types...> const *>(bytes);
    }
};

double origin_ip_address_score(ip_header const &ip);

std::string oui_manufacturer_name(macaddr const &macaddr);

std::string services_port_name(int port, std::string const &proto /* tcp,udp */);

sockaddr sockaddr_from_string(const std::string &src, sa_family_t sin_family = AF_INET);

std::string maybe_obfuscate_address_string(std::string_view address);

template <typename address_type> inline std::string maybe_obfuscate_address(address_type &&a) { return maybe_obfuscate_address_string(str(a)); }
inline double timeval_to_unixtime(timeval const &tv) { return tv.tv_sec + tv.tv_usec / 1e6; }
