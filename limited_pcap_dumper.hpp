#pragma once

#include "space_estimate_for_path.hpp"
#include "env.hpp"
#include "wire_layout.hpp"

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
    in_addr_t guessed_ip = 0;
    int guessed_ip_ttl = -1;
    std::unordered_set<uint16_t> answering_ports;

    bool can_write_bytes(uintmax_t len) {
        auto ret = pcap_filesize + len < env("limited_pcap_dumper_max_dump_bytes", 100 * 1024 * 1024)
                   && space_estimate_for_path(pcap_dir, len) >=
                      env("limited_pcap_dumper_min_available_bytes", 1 * 1024 * 1024 * 1024);
        if (ret) {
            pcap_filesize += len;
        }
        return ret;
    }

    void note_ip_header(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto ip = *(ip_header const*)(bytes + sizeof(ether_header));

        if (guessed_ip_ttl < ip.ip_ttl) {
            guessed_ip = ip.ip_src.s_addr;
            guessed_ip_ttl = ip.ip_ttl;
        }
        if (h->caplen >= sizeof(ether_header) + sizeof(ip_header) + sizeof(tcp_header) && ip.ip_p == (uint8_t)IPProtocol::TCP) {
            auto tcp = *(tcp_header const*)(bytes + sizeof(ether_header) + sizeof(ip_header));
            if (guessed_ip == ip.ip_src.s_addr &&
                    (tcp.th_flags & ((uint8_t)TCPFlags::SYN|(uint8_t)TCPFlags::ACK))
                == ((uint8_t)TCPFlags::SYN|(uint8_t)TCPFlags::ACK)) {
                answering_ports.insert(ntohs(tcp.th_sport));
            }
        }
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

    void report_html_dumper(macaddr const&mac, std::ostream& out) {
        sockaddr_in sa;
        std::memset(&sa,0,sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = guessed_ip;
        char dns[1024];
        auto ret = getnameinfo((struct sockaddr*)&sa,sizeof(sa),dns,sizeof(dns),0,0,0);
        std::string dns_str = ret ? gai_strerror(ret) : dns;

        out << "<h2>" << mac << " "
            << sa.sin_addr << " "
            << dns_str
            << "</h2>\n";
        out << "<p><a href=\"" << pcap_filename << "\">pcap</a></p>\n";
        in_addr my_addr;
        my_addr.s_addr = guessed_ip;
        if (!answering_ports.empty()) {
            out << "<ul>\n";
            for (auto&&port:answering_ports) {
                out << "\t<li><a href=\"http://" << my_addr << ":" << port << "\">" << port << "</a></li>\n";
            }
            out << "</ul>\n";
        }
    }
};