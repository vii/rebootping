#include "ping_record_store.hpp"
#include "network_flat_records.hpp"
#include "rebootping_records_dir.hpp"

#include <mutex>

namespace {
    uint64_t uint64_random() {
        static std::random_device random_device;
        static std::mt19937_64 random_engine{random_device()};
        static std::uniform_int_distribution<uint64_t> distro{
                std::numeric_limits<std::uint64_t>::min(),
                std::numeric_limits<std::uint64_t>::max()};
        return distro(random_engine);
    }

}// namespace

void ping_record_store_prepare(sockaddr const &src_addr, sockaddr const &dst_addr, std::string_view ping_if, rebootping_icmp_payload &ping_payload) {
    ping_payload.ping_cookie = uint64_random();
    ping_payload.ping_start_unixtime = now_unixtime();

    auto dst_network_addr = network_addr_from_sockaddr(dst_addr);
    flat_bytes_interned_tag if_tag;
    write_locked_reference(ping_record_store())->add_flat_record(ping_payload.ping_start_unixtime, [&](auto &&record) {
        record.ping_start_unixtime() = ping_payload.ping_start_unixtime;
        record.ping_sent_seconds() = std::nan("");
        record.ping_recv_seconds() = std::nan("");
        record.ping_dest_addr() = dst_network_addr;
        record.ping_interface() = ping_if;
        if_tag = record.ping_interface().flat_bytes_offset;
        record.ping_cookie() = ping_payload.ping_cookie;
        ping_payload.ping_slot = record.flat_iterator_index;
    });
    {
        auto write = write_locked_reference(last_ping_record_store());
        auto last_ping = write->ping_if_ip_index(std::make_pair(ping_if, dst_network_addr)).add_if_missing(ping_payload.ping_start_unixtime);
        last_ping.ping_slot() = ping_payload.ping_slot;
        last_ping.ping_start_unixtime() = ping_payload.ping_start_unixtime;
    }
}

void ping_record_store_process_one_icmp_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
    auto packet = rebootping_ether_packet::header_from_packet(bytes, h->caplen);
    if (!packet) {
        return;
    }
    if (ntohs(packet->ether_type_or_len) != (uint16_t) ether_type::IPv4) {
        return;
    }
    if (packet->ip_p != (uint8_t) ip_protocol::ICMP) {
        return;
    }

    auto &ping_payload = *packet;
    auto lock = write_locked_reference(ping_record_store());
    auto *timeshard = lock->unixtime_to_timeshard(ping_payload.ping_start_unixtime);
    if (!timeshard) {
        std::cout << "ping_record_store_process_packet cannot find timeshard for " << (now_unixtime() - ping_payload.ping_start_unixtime) << " seconds ago";
        return;
    }
    if (timeshard->timeshard_header_ref().flat_timeshard_index_next <= ping_payload.ping_slot) {
        std::cout << "record_store_process_packet overflow timeshard for " << (now_unixtime() - ping_payload.ping_start_unixtime) << " seconds ago; slot " << ping_payload.ping_slot;
        return;
    }
    if (timeshard->flat_timeshard_index_next() <= ping_payload.ping_slot) {
        std::cout << "record_store_process_packet; ping_slot too large " << std::endl;
        dbg(timeshard->flat_timeshard_index_next(), ping_payload.ping_slot);
        return;
    }
    auto record = timeshard->timeshard_iterator_at(ping_payload.ping_slot);
    if (ping_payload.ping_cookie != record.ping_cookie()) {
        std::cout << "record_store_process_packet bad cookie for " << (now_unixtime() - ping_payload.ping_start_unixtime) << " seconds ago";
        return;
    }

    switch (packet->icmp_type) {
        case (uint8_t) icmp_type::ECHO:
            record.ping_sent_seconds() = now_unixtime() - record.ping_start_unixtime();
            break;
        case (uint8_t) icmp_type::ECHOREPLY:
            record.ping_recv_seconds() = now_unixtime() - record.ping_start_unixtime();
            break;
        default:
            break;
    }
}

locked_reference<ping_record> &ping_record_store() {
    static locked_holder<ping_record> store(rebootping_records_dir());
    return store;
}

locked_reference<last_ping_record> &last_ping_record_store() {
    static locked_holder<last_ping_record> store(rebootping_records_dir());
    return store;
}

locked_reference<unanswered_ping_record> &unanswered_ping_record_store() {
    static locked_holder<unanswered_ping_record> store(rebootping_records_dir());
    return store;
}
