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
FIN	= 0x01,
SYN	= 0x02,
RST	= 0x04,
PUSH = 0x08,
ACK	= 0x10,
URG = 0x20,
ECNECHO = 0x40,
CWR = 0x80,
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

    auto inline operator==(macaddr const &other) const {
        return as_number() == other.as_number();
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
    macaddr ether_dhost;    /* destination eth addr	*/
    macaddr ether_shost;    /* source ether addr	*/
    u_int16_t ether_type;                /* packet type ID field	*/
} __attribute__ ((__packed__));
struct ip_header {
    u_int8_t ip_vhl;        /* header length, version */
    u_int8_t ip_tos;        /* type of service */
    u_int16_t ip_len;        /* total length */
    u_int16_t ip_id;        /* identification */
    u_int16_t ip_off;        /* fragment offset field */
    u_int8_t ip_ttl;        /* time to live */
    u_int8_t ip_p;        /* protocol */
    u_int16_t ip_sum;        /* checksum */
    struct in_addr ip_src, ip_dst;
} __attribute__ ((__packed__));

struct tcp_header {
    u_int16_t	th_sport;		/* source port */
    u_int16_t	th_dport;		/* destination port */
    u_int32_t   th_seq;			/* sequence number */
    u_int32_t   th_ack;			/* acknowledgement number */
    u_int8_t	th_offx2;		/* data offset, rsvd */
    u_int8_t	th_flags;
    u_int16_t	th_win;			/* window */
    u_int16_t	th_sum;			/* checksum */
    u_int16_t	th_urp;			/* urgent pointer */
} __attribute__ ((__packed__));

struct icmp_header {
    u_int8_t icmp_type;        /* type of message, see below */
    u_int8_t icmp_code;        /* type sub code */
    u_int16_t icmp_cksum;        /* ones complement cksum of struct */
    union {
        u_int8_t ih_pptr;            /* ICMP_PARAMPROB */
        struct in_addr ih_gwaddr;    /* ICMP_REDIRECT */
        struct ih_idseq {
            u_int16_t icd_id;
            u_int16_t icd_seq;
        } ih_idseq;
        uint32_t ih_void;
    } icmp_hun;
} __attribute__ ((__packed__));
