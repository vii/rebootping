#pragma once

#include "space_estimate_for_path.hpp"
#include "env.hpp"
#include "wire_layout.hpp"
#include "event_tracker.hpp"
#include "str.hpp"

#include <pcap/pcap.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <atomic>
#include <unordered_map>
#include <unordered_set>

struct limited_pcap_dumper {
    std::string pcap_filename;
    std::filesystem::path pcap_dir;
    pcap_dumper_t *pcap_dumper = nullptr;
    std::uintmax_t pcap_filesize = 0;

    bool can_write_bytes(uintmax_t len) {
        auto ret = pcap_filesize + len < env("limited_pcap_dumper_max_dump_bytes", 100 * 1024 * 1024)
                   && space_estimate_for_path(pcap_dir, len) >=
                      env("limited_pcap_dumper_min_available_bytes", 1 * 1024 * 1024 * 1024);
        if (ret) {
            pcap_filesize += len;
        }
        return ret;
    }

    void note_ip_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto const &ether = *(ether_header const *) bytes;
        auto const &ip = *(ip_header const *) (bytes + sizeof(ether_header));

        if (h->caplen >= sizeof(ether_header) + sizeof(ip_header) + sizeof(tcp_header) &&
            ip.ip_p == (uint8_t) IPProtocol::TCP) {
            auto tcp = *(tcp_header const *) (bytes + sizeof(ether_header) + sizeof(ip_header));
            if ((tcp.th_flags & ((uint8_t) TCPFlags::SYN | (uint8_t) TCPFlags::ACK))
                == ((uint8_t) TCPFlags::SYN | (uint8_t) TCPFlags::ACK)) {
                event_tracker.add_event(
                        {str("tcp_accept ", ether.ether_shost),},
                        {{"port",   uint64_t(ntohs(tcp.th_sport))
                         },
                         {"ip_src", str(ip.ip_src)}}
                );
            }
        }
    }

    void note_arp_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
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
        event_tracker.add_event(
                {"arp_reply", str("arp_reply ", ether.ether_shost)},
                {{
                         "ip_s_addr", uint64_t{arp.arp_spa.s_addr}
                 },
                 {       "requestor", str(arp.arp_target)}}
        );
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

        auto last_arp = event_tracker.last_event_for_key(str("arp_reply ", mac));
        if (last_arp) {
            sockaddr_in sa;
            std::memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = uint32_t(std::get<uint64_t>((*last_arp)["ip_s_addr"]));
            char dns[1024];
            auto ret = getnameinfo((struct sockaddr *) &sa, sizeof(sa), dns, sizeof(dns), 0, 0, 0);
            dns_str = ret ? gai_strerror(ret) : dns;
        }

        out << "<h2>" << mac << " "
            << oui_manufacturer_name(mac) << " "
            << dns_str
            << "</h2>\n";
        out << "<p><a href=\"" << pcap_filename << "\">pcap</a></p>\n";
        std::unordered_map<uint64_t, uint64_t> count;
        event_tracker.walk_key(str("tcp_accept ", mac), [&](auto &&accept) {
            ++count[std::get<uint64_t>(accept["port"])];
            return true;
        });

        if (!count.empty()) {
            out << "<ul>\n";
            for (auto&&[port, calls]:count) {
                out << "\t<li>port <a href=\"http://" << dns_str << ":" << port << "\">" << port << "</a> accepted "
                    << calls << " times</li>\n";
            }
            out << "</ul>\n";
        }
    }
};