#include "ping_record_store.hpp"

namespace {
    double timeval_to_unixtime(timeval const &tv) {
        return tv.tv_sec + tv.tv_usec / 1e6;
    }
}

ping_record *ping_record_store::process_one_icmp_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
    if (h->caplen < sizeof(rebootping_ether_packet)) {
        return nullptr;
    }
    auto packet = (rebootping_ether_packet const *) bytes;
    if (ntohs(packet->packet_ether.ether_type) != (uint16_t) EtherType::IPv4) {
        return nullptr;
    }
    if (packet->packet_ip.ip_p != (uint8_t) IPProtocol::ICMP) {
        return nullptr;
    }
    auto const &payload = packet->packet.packet_payload;
    if (payload.rebootping_slot >= ping_records.size()) {
        return nullptr;
    }
    auto &record = ping_records[payload.rebootping_slot];
    if (payload.rebootping_cookie != record.ping_cookie) {
        return nullptr;
    }
    auto ping_type = str("icmp_", packet->packet.packet_icmp.icmp_type);

    switch (packet->packet.packet_icmp.icmp_type) {
        case (uint8_t) ICMPType::ECHO:
            record.ping_sent_unixtime = timeval_to_unixtime(h->ts);
            ping_type = "icmp_echo";
            break;
        case (uint8_t) ICMPType::ECHOREPLY:
            record.ping_recv_unixtime = timeval_to_unixtime(h->ts);
            ping_type = "icmp_echoreply";
            break;
        default:
            break;
    }


    track_ping(ping_type, record);
    return &record;
}

size_t ping_record_store::add_ping_record(ping_record &&record) {
    auto suffix = str(" to ", record.ping_dest_addr, " if ", record.ping_interface);

    track_ping("ping_launch", record);

    auto pos = ping_next_record.fetch_add(1) % ping_records.capacity();
    ping_records[pos] = std::move(record);

    return pos;
}

event_tracker_contents ping_record_store::track_ping(const std::string &ping_type, const ping_record &record) {
    auto ret = event_tracker.add_event(
            {
                    ping_type,
                    str(ping_type, " to ", record.ping_dest_addr),
                    str(ping_type, " to ", record.ping_dest_addr, " if ", record.ping_interface),
                    str(ping_type, " if ", record.ping_interface),
            },
            {
                    {"ping_start_unixtime", record.ping_start_unixtime},
                    {"ping_sent_unixtime",  record.ping_sent_unixtime},
                    {"ping_recv_unixtime",  record.ping_recv_unixtime},
                    {"ping_interface",      record.ping_interface},
                    {"ping_dest_addr",      str(record.ping_dest_addr)},
                    {"ping_type",           ping_type},
            }
    );

    return ret;
}

ping_record::ping_record() {
    std::memset(&ping_dest_addr, 0, sizeof(ping_dest_addr));
}
