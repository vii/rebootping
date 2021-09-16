#include "network_interface_watcher.hpp"
#include "make_unique_ptr_closer.hpp"

namespace {
    void note_dns_udp_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto p = wire_header<ether_header, ip_header, udp_header, dns_header>::header_from_packet(bytes, h->caplen);
        if (!p) {
            return;
        }
        std::cout << "note_dns_udp_packet_recv " << p->dns_id << " answers " << p->dns_answers << std::endl;
    }

    void note_tcp_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto p = wire_header<
                ether_header,
                ip_header,
                tcp_header>::header_from_packet(bytes, h->caplen);
        if (!p) {
            return;
        }

        if ((p->th_flags & ((uint8_t) TCPFlags::SYN | (uint8_t) TCPFlags::ACK)) == ((uint8_t) TCPFlags::SYN | (uint8_t) TCPFlags::ACK)) {
            auto port = ntohs(p->th_sport);
            if (port < env("tcp_recv_tracking_min_port", 30000)) {
                global_event_tracker.add_event(
                        {
                                str("tcp_accept ", p->ether_shost),
                        },
                        {{"port", uint64_t(port)},
                         {"ip_src", str(p->ip_src)}});
            }
        }
    }


    void note_udp_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto p = wire_header<
                ether_header,
                ip_header,
                udp_header>::header_from_packet(bytes, h->caplen);
        if (!p) {
            return;
        }

        auto port = ntohs(p->uh_dport);
        if (port < env("udp_recv_tracking_min_port", 10000)) {
            global_event_tracker.add_event(
                    {
                            str("udp_recv ", p->ether_dhost),
                    },
                    {{"port", uint64_t(port)},
                     {"ip_dst", str(p->ip_dst)}});
        }

        if (auto dns_p = wire_header<ether_header, ip_header, udp_header, dns_header>::header_from_packet(bytes, h->caplen)) {
            if (ntohs(dns_p->uh_sport) == 53 || ntohs(dns_p->uh_dport) == 53) {
                note_dns_udp_packet(h, bytes);
            }
        }
    }

    void note_ip_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto p = wire_header<
                ether_header,
                ip_header>::header_from_packet(bytes, h->caplen);

        switch (p->ip_p) {
            case (uint8_t) IPProtocol::UDP:
                note_udp_packet(h, bytes);
                break;
            case (uint8_t) IPProtocol::TCP:
                note_tcp_packet(h, bytes);
                break;
        }
    }

    void note_arp_packet_sent(const struct pcap_pkthdr *h, const u_char *bytes) {
        auto p = wire_header<
                ether_header,
                arp_header>::header_from_packet(bytes, h->caplen);
        if (!p) {
            return;
        }

        if (ntohs(p->arp_oper) != (uint16_t) ARPOperation::ARP_REPLY) {
            return;
        }
        if (ntohs(p->arp_ptype) != (uint16_t) EtherType::IPv4) {
            return;
        }
        if (p->arp_plen != sizeof(in_addr)) {
            return;
        }
        if (p->arp_sender != p->ether_shost) {
            return;
        }
        global_event_tracker.add_event(
                {"arp_reply", str("arp_reply ", p->ether_shost)},
                {
                        {"ip_src", str(p->arp_spa)},
                        {"requestor", str(p->arp_target)},
                });
    }
}// namespace

void network_interface_watcher::learn_from_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
    auto ether = wire_header<ether_header>::header_from_packet(bytes, h->caplen);
    if (!ether) {
        return;
    }

    switch (ntohs(ether->ether_type)) {
        case (uint16_t) EtherType::IPv4:
            note_ip_packet(h, bytes);

            if (auto p = wire_header<ether_header, ip_header>::header_from_packet(bytes, h->caplen)) {
                if (p->ip_p == (uint8_t) IPProtocol::ICMP) {
                    ping_record_store_process_one_icmp_packet(h, bytes);
                }
            }
            break;
        case (uint16_t) EtherType::ARP:
            note_arp_packet_sent(h, bytes);
            break;
    }
}

void network_interface_watcher::learn_from_pcap_file(std::string const &filename) {
    network_interface_watcher watcher(filename);
    char errbuf[PCAP_ERRBUF_SIZE];

    auto pcap = pcap_open_offline(filename.c_str(), errbuf);

    if (!pcap) {
        throw std::runtime_error(str("learn_from_pcap_file failed on ", filename, ": ", errbuf));
    }
    auto pcap_closer = make_unique_ptr_closer(pcap, [](pcap_t *p) {
        if (p) {
            pcap_close(p);
        }
    });
    auto ret = pcap_loop(
            pcap,
            -1 /*cnt*/,
            [](u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
                ((network_interface_watcher *) user)->learn_from_packet(h, bytes);
            },
            (u_char *) &watcher);
    if (ret == -1) {
        throw std::runtime_error(str("pcap_loop failed on ", filename, ": ", pcap_geterr(pcap)));
    }
}


network_interface_watcher_live::network_interface_watcher_live(std::string_view name)
    : network_interface_watcher(name),
      interface_thread(&network_interface_watcher_live::run_watcher_loop, this) {
}

void network_interface_watcher_live::run_watcher_loop() {
    try {
        open_and_process_packets();
    } catch (...) {
        interface_has_stopped.store(true);
        throw;
    }
    interface_has_stopped.store(true);
}

void network_interface_watcher_live::open_and_process_packets() {
    char errbuf[PCAP_ERRBUF_SIZE];
    interface_pcap = pcap_open_live(
            interface_name.c_str(),
            10 * 1024,//sizeof(rebootping_ether_packet) /* snaplen */,
            1 /* promiscuous */,
            1 /* packet buffer timeout in ms; allows buffering up to 1ms of packets. See https://www.tcpdump.org/manpages/pcap.3pcap.html */,
            errbuf);
    if (!interface_pcap) {
        std::cerr << "pcap_open_live " << interface_name << " " << errbuf << std::endl;
        return;
    }
    auto pcap_closer = make_unique_ptr_closer(interface_pcap, [](pcap_t *p) {
        if (p) {
            pcap_close(p);
        }
    });
    /* filter all non ICMP traffic
    bpf_program filter;
    auto c = pcap_compile(interface_pcap, &filter, "proto 1", 1 // optimize
    , PCAP_NETMASK_UNKNOWN);
    if (c == 0) {
        auto sf = pcap_setfilter(interface_pcap, &filter);
        if (sf != 0) {
            std::cerr << "pcap_setfilter failed " << pcap_geterr(interface_pcap) << std::endl;
        }
    } else {
        std::cerr << "pcap_compile failed " << pcap_geterr(interface_pcap) << std::endl;
    }
    */

    // TODO add structured logging
    std::cerr << "Polling interface " << interface_name << std::endl;
    while (!interface_should_stop) {
        auto ret = pcap_loop(
                interface_pcap,
                -1 /*cnt*/,
                [](u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
                    ((network_interface_watcher_live *) user)->process_one_packet(h, bytes);
                },
                (u_char *) this);
        if (ret == -1) {
            std::cerr << "pcap_loop " << interface_name << " " << pcap_geterr(interface_pcap) << std::endl;
            break;
        }
    }
}

limited_pcap_dumper &network_interface_watcher_live::dumper_for_macaddr(const macaddr &ma) {
    std::lock_guard _{watcher_mutex};
    auto i = interface_dumpers.find(ma);
    if (i == interface_dumpers.end()) {
        i = interface_dumpers.insert(
                                     std::make_pair(
                                             ma,
                                             std::make_unique<limited_pcap_dumper>(
                                                     interface_pcap,
                                                     str("dump_", interface_name, "_", ma, ".pcap"))))
                    .first;
    }
    return *i->second;
}

void network_interface_watcher_live::process_one_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
    if (auto ether = wire_header<ether_header>::header_from_packet(bytes, h->caplen)) {
        auto dest_dumper = existing_dumper_for_macaddr(ether->ether_dhost);
        auto &source_dumper = dumper_for_macaddr(ether->ether_shost);
        if (dest_dumper) {
            dest_dumper->pcap_dump_packet(h, bytes);
        }
        source_dumper.pcap_dump_packet(h, bytes);
    }
    learn_from_packet(h, bytes);
    if (interface_should_stop.load()) {
        pcap_breakloop(interface_pcap);
    }
}

network_interface_watcher_live::~network_interface_watcher_live() {
    interface_should_stop.store(true);
    interface_thread.join();
}

limited_pcap_dumper *network_interface_watcher_live::existing_dumper_for_macaddr(const macaddr &ma) {
    std::lock_guard _{watcher_mutex};
    auto i = interface_dumpers.find(ma);
    if (i == interface_dumpers.end()) {
        return nullptr;
    }
    return i->second.get();
}
