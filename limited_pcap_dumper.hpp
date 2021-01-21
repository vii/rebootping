#pragma once

#include "env.hpp"
#include "event_tracker.hpp"
#include "space_estimate_for_path.hpp"
#include "str.hpp"
#include "wire_layout.hpp"

#include <atomic>
#include <filesystem>
#include <iostream>
#include <pcap/pcap.h>
#include <string>
#include <unordered_map>
#include <unordered_set>

struct limited_pcap_dumper {
    std::string pcap_filename;
    std::filesystem::path pcap_dir;
    pcap_dumper_t *pcap_dumper = nullptr;
    std::uintmax_t pcap_filesize = 0;

    bool can_write_bytes(uintmax_t len) {
        auto ret = pcap_filesize + len < env("limited_pcap_dumper_max_dump_bytes", 100 * 1024 * 1024) && space_estimate_for_path(pcap_dir, len) >=
                                                                                                                 env("limited_pcap_dumper_min_available_bytes", 1 * 1024 * 1024 * 1024);
        if (ret) {
            pcap_filesize += len;
        }
        return ret;
    }

    void note_dns_udp_packet_recv(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto const &ether = *(ether_header const *) bytes;
        auto const &ip = *(ip_header const *) (bytes + sizeof(ether_header));
        auto const &udp = *(udp_header const *) (bytes + sizeof(ether_header) + sizeof(ip_header));
        auto const &dns = *(dns_header const *) (bytes + sizeof(ether_header) + sizeof(ip_header) + sizeof(udp_header));
    }


    void note_ip_packet_recv(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto const &ether = *(ether_header const *) bytes;
        auto const &ip = *(ip_header const *) (bytes + sizeof(ether_header));
        if (h->caplen >= sizeof(ether_header) + sizeof(ip_header) + sizeof(udp_header) && ip.ip_p == (uint8_t) IPProtocol::UDP) {
            auto udp = *(udp_header const *) (bytes + sizeof(ether_header) + sizeof(ip_header));
            auto port = ntohs(udp.uh_dport);
            if (port < env("udp_recv_tracking_min_port", 10000)) {
                global_event_tracker.add_event(
                        {
                                str("udp_recv ", ether.ether_shost),
                        },
                        {{"port", uint64_t(port)},
                         {"ip_dst", str(ip.ip_dst)}});
            }
            if (ntohs(udp.uh_sport) == 53 && h->caplen >= sizeof(ether_header) + sizeof(ip_header) + sizeof(udp_header) + sizeof(dns_header)) {
                note_dns_udp_packet_recv(h, bytes);
            }
        }
    }

    void note_ip_packet_sent(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto const &ether = *(ether_header const *) bytes;
        auto const &ip = *(ip_header const *) (bytes + sizeof(ether_header));

        if (h->caplen >= sizeof(ether_header) + sizeof(ip_header) + sizeof(tcp_header) &&
            ip.ip_p == (uint8_t) IPProtocol::TCP) {
            auto tcp = *(tcp_header const *) (bytes + sizeof(ether_header) + sizeof(ip_header));
            if ((tcp.th_flags & ((uint8_t) TCPFlags::SYN | (uint8_t) TCPFlags::ACK)) == ((uint8_t) TCPFlags::SYN | (uint8_t) TCPFlags::ACK)) {
                auto port = ntohs(tcp.th_sport);
                if (port < env("tcp_recv_tracking_min_port", 30000)) {
                    global_event_tracker.add_event(
                            {
                                    str("tcp_accept ", ether.ether_shost),
                            },
                            {{"port", uint64_t(port)},
                             {"ip_src", str(ip.ip_src)}});
                }
            }
        }
    }

    void note_arp_packet_sent(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto const &ether = *(ether_header const *) bytes;
        auto const &arp = *(arp_header const *) (bytes + sizeof(ether_header));

        if (ntohs(arp.arp_oper) != (uint16_t) ARPOperation::ARP_REPLY) {
            return;
        }
        if (ntohs(arp.arp_ptype) != (uint16_t) EtherType::IPv4) {
            return;
        }
        if (arp.arp_plen != sizeof(in_addr)) {
            return;
        }
        if (arp.arp_sender != ether.ether_shost) {
            return;
        }
        global_event_tracker.add_event(
                {"arp_reply", str("arp_reply ", ether.ether_shost)},
                {
                        {"ip_src", str(arp.arp_spa)},
                        {"requestor", str(arp.arp_target)},
                });
    }


    limited_pcap_dumper(pcap_t *pcap_session, std::string const &filename)
        : pcap_filename(filename),
          pcap_dir(std::filesystem::absolute(std::filesystem::path(filename)).parent_path()) {
        std::error_code file_size_check_error;
        auto size = std::filesystem::file_size(pcap_filename, file_size_check_error);
        if (!file_size_check_error) {
            pcap_filesize = size;
        }
        if (can_write_bytes(sizeof(pcap_file_header))) {
            pcap_dumper = pcap_dump_open_append(pcap_session, pcap_filename.c_str());
            if (!pcap_dumper) {
                std::cerr << "pcap_dump_open_append " << pcap_filename << ": " << pcap_geterr(pcap_session)
                          << std::endl;
            }
        }
    }

    void pcap_dump_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
        if (!pcap_dumper) {
            return;
        }
        if (!can_write_bytes(sizeof(pcap_pkthdr) + h->caplen)) {
            close_dumper();
            return;
        }
        pcap_dump((u_char *) pcap_dumper, h, bytes);
        auto flush_ret = pcap_dump_flush(pcap_dumper);
        if (flush_ret != 0) {
            std::cerr << "pcap_dump_flush " << pcap_filename << ": failed" << std::endl;
        }
    }

    ~limited_pcap_dumper() {
        close_dumper();
    }

    void close_dumper() {
        if (pcap_dumper) {
            pcap_dump_close(pcap_dumper);
            pcap_dumper = nullptr;
        }
    }

    limited_pcap_dumper(limited_pcap_dumper const &) = delete;

    limited_pcap_dumper &operator=(limited_pcap_dumper const &) = delete;

    void report_html_dumper(macaddr const &mac, std::ostream &out) {
        std::string dns_str;

        auto last_arp = global_event_tracker.last_event_for_key(str("arp_reply ", mac));
        if (last_arp) {
            auto const ip_src = std::get<std::string>((*last_arp)["ip_src"]);
            auto sockaddr = sockaddr_from_string(ip_src);
            char dns[1024];
            auto ret = getnameinfo((struct sockaddr *) &sockaddr, sizeof(sockaddr), dns, sizeof(dns), 0, 0, 0);
            dns_str = ret ? gai_strerror(ret) : dns;
        }

        out << "<h2>" << maybe_obfuscate_address(mac) << " "
            << oui_manufacturer_name(mac) << " "
            << maybe_obfuscate_address(dns_str)
            << "</h2>\n";
        out << "<p><a href=\"" << pcap_filename << "\">pcap</a></p>\n";
        std::unordered_map<uint64_t, uint64_t> tcp_accept;
        global_event_tracker.walk_key(str("tcp_accept ", mac), [&](auto &&accept) {
            ++tcp_accept[std::get<uint64_t>(accept["port"])];
            return true;
        });

        out << "<ul>\n";
        for (auto const &[port, calls] : tcp_accept) {
            auto service = services_port_name(
                    port,
                    "tcp");
            auto browser_service = service.empty() ? "http" : service;
            out << "\t<li>tcp port <a href=\""
                << browser_service
                << "://" << dns_str << ":" << port << "\">" << port << " " << service << "</a> accepted "
                << calls << " times</li>\n";
        }

        std::unordered_map<uint64_t, uint64_t> udp_recv;
        global_event_tracker.walk_key(str("udp_recv ", mac), [&](auto &&recv) {
            ++udp_recv[std::get<uint64_t>(recv["port"])];
            return true;
        });
        for (auto const &[port, calls] : udp_recv) {
            if (calls < env("udp_recv_min_reported", 2)) {
                continue;
            }
            auto service = services_port_name(
                    port,
                    "udp");
            out << "\t<li>udp port " << port << " " << service << " received "
                << calls << " times</li>\n";
        }
        out << "</ul>\n";
    }
};