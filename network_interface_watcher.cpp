#include "network_interface_watcher.hpp"
#include "make_unique_ptr_closer.hpp"

network_interface_watcher::network_interface_watcher(std::string name, ping_record_store &store)
        : interface_name(std::move(name)),
          interface_thread(&network_interface_watcher::run_watcher_loop, this),
          ping_store{store} {
}

void network_interface_watcher::run_watcher_loop() {
    try {
        open_and_process_packets();
    } catch (...) {
        interface_has_stopped.store(true);
        throw;
    }
    interface_has_stopped.store(true);
}

void network_interface_watcher::open_and_process_packets() {
    char errbuf[PCAP_ERRBUF_SIZE];
    interface_pcap = pcap_open_live(
            interface_name.c_str(),
            10 * 1024, //sizeof(rebootping_ether_packet) /* snaplen */,
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

    while (!interface_should_stop) {
        auto ret = pcap_loop(
                interface_pcap,
                -1 /*cnt*/,
                [](u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
                    ((network_interface_watcher *) user)->process_one_packet(h, bytes);
                },
                (u_char *) this
        );
        if (ret == -1) {
            std::cerr << "pcap_loop " << interface_name << " " << pcap_geterr(interface_pcap) << std::endl;
            break;
        }
    }
}

limited_pcap_dumper &network_interface_watcher::dumper_for_macaddr(const macaddr &ma) {
    std::lock_guard _{watcher_mutex};
    auto i = interface_dumpers.find(ma);
    oui_manufacturer_name(ma);
    if (i == interface_dumpers.end()) {
        i = interface_dumpers.insert(
                std::make_pair(
                        ma,
                        std::make_unique<limited_pcap_dumper>(
                                interface_pcap,
                                str("dump_", interface_name, "_", ma, ".pcap")
                        )
                )
        ).first;
    }
    return *i->second;
}

void network_interface_watcher::process_one_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
    if (h->caplen >= sizeof(ether_header)) {
        auto ether = (ether_header *) bytes;
        auto dest_dumper = existing_dumper_for_macaddr(ether->ether_dhost);
        auto &source_dumper = dumper_for_macaddr(ether->ether_shost);
        if (dest_dumper) {
            dest_dumper->pcap_dump_packet(h, bytes);
        }
        source_dumper.pcap_dump_packet(h, bytes);

        switch (ntohs(ether->ether_type)) {
            case (uint16_t) EtherType::IPv4:
                if (
                        h->caplen >= sizeof(ether_header) + sizeof(ip_header)) {
                    {
                        std::lock_guard _{watcher_mutex};
                        source_dumper.note_ip_packet(h, bytes);
                    }
                    auto ip = *(ip_header const *) (bytes + sizeof(ether_header));

                    if (ip.ip_p == (uint8_t) IPProtocol::ICMP) {
                        ping_store.process_one_icmp_packet(h, bytes);
                    }
                }
                break;
            case (uint16_t) EtherType::ARP:
                if (h->caplen >= sizeof(ether_header) + sizeof(arp_header)) {
                    std::lock_guard _{watcher_mutex};
                    source_dumper.note_arp_packet(h, bytes);
                }
                break;
        }
    }
    if (interface_should_stop.load()) {
        pcap_breakloop(interface_pcap);
    }
}

network_interface_watcher::~network_interface_watcher() {
    interface_should_stop.store(true);
    interface_thread.join();
}

limited_pcap_dumper *network_interface_watcher::existing_dumper_for_macaddr(const macaddr &ma) {
    std::lock_guard _{watcher_mutex};
    auto i = interface_dumpers.find(ma);
    if (i == interface_dumpers.end()) {
        return nullptr;
    }
    return i->second.get();
}
