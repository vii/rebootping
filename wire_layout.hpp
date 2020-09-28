#pragma once

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


enum class IPProtocol : uint8_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
};

enum class ICMPType : uint8_t {
    ECHOREPLY = 0,
    ECHO = 8,
};

enum class EtherType : uint16_t {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
};
enum class TCPFlags : uint8_t {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PUSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
    ECNECHO = 0x40,
    CWR = 0x80,
};
enum class ARPOperation : uint16_t {
    ARP_WHO_HAS = 1,
    ARP_REPLY = 2,
};

constexpr auto ETH_ALEN = 6;

struct macaddr {
    uint8_t mac_bytes[ETH_ALEN];

    [[nodiscard]] inline uint64_t as_number() const {
        uint64_t as_num = 0;
        for (auto c:mac_bytes) {
            as_num <<= 8;
            as_num += c;
        }
        return as_num;
    }

    inline uint32_t mac_manufacturer() const {
        return (uint32_t) (as_number() >> 24);
    }

    auto inline operator==(macaddr const &other) const {
        return as_number() == other.as_number();
    }

    auto inline operator!=(macaddr const &other) const {
        return as_number() != other.as_number();
    }
} __attribute__ ((__packed__));


inline std::ostream &operator<<(std::ostream &os, macaddr const &m) {
    const char *hex_digits = "0123456789abcdef";
    bool first = true;
    for (auto c:m.mac_bytes) {
        if (!first) {
            os << ":";
        }
        os << hex_digits[c / 16] << hex_digits[c % 16];
        first = false;
    }
    return os;
}

namespace std {
    template<>
    struct hash<macaddr> {
        inline size_t operator()(macaddr const &ma) const {
            return std::hash<uint64_t>()(ma.as_number());
        }
    };
}

std::ostream &operator<<(std::ostream &os, in_addr const &i);


std::ostream &operator<<(std::ostream &os, sockaddr const &s);

struct ether_header {
    macaddr ether_dhost;
    macaddr ether_shost;
    u_int16_t ether_type;
} __attribute__ ((__packed__));
struct ip_header {
    u_int8_t ip_vhl;
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
} __attribute__ ((__packed__));

struct tcp_header {
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
    u_int8_t th_offx2;
    u_int8_t th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
} __attribute__ ((__packed__));

struct icmp_header {
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
} __attribute__ ((__packed__));

struct arp_header {
    u_int16_t arp_htype;
    u_int16_t arp_ptype;
    u_int8_t arp_hlen;
    u_int8_t arp_plen;
    u_int16_t arp_oper;
    macaddr arp_sender;
    in_addr arp_spa;
    macaddr arp_target;
    in_addr arp_tpa;
} __attribute__ ((__packed__));

struct udp_header {
    u_int16_t uh_sport;
    u_int16_t uh_dport;
    u_int16_t uh_len;
    u_int16_t uh_sum;
};

double origin_ip_address_score(ip_header const &ip);

std::string oui_manufacturer_name(macaddr const &macaddr);

std::string services_port_name(int port, std::string const &proto /* tcp,udp */);