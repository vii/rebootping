#include "ping_record_store.hpp"
#include "flat_record.hpp"
#include "rebootping_records_dir.hpp"


namespace {
    double timeval_to_unixtime(timeval const &tv) {
        return tv.tv_sec + tv.tv_usec / 1e6;
    }

    define_flat_record(ping_record,
                       (double, ping_start_unixtime),
                       (double, ping_sent_seconds),
                       (double, ping_recv_seconds),
                       (std::string_view, ping_dest_addr),
                       (std::string_view, ping_interface),
                       (uint64_t, ping_cookie), );

    ping_record &ping_record_store() {
        static ping_record store(rebootping_records_dir());
        return store;
    }

    std::mutex &ping_record_store_mutex() {
        static std::mutex m;
        return m;
    }

    uint64_t uint64_random() {
        static std::random_device random_device;
        static std::mt19937_64 random_engine{random_device()};
        static std::uniform_int_distribution<uint64_t> distro{
                std::numeric_limits<std::uint64_t>::min(),
                std::numeric_limits<std::uint64_t>::max()};
        return distro(random_engine);
    }

}// namespace

void ping_record_store_prepare(std::string_view dest_addr, std::string_view ping_if, rebootping_icmp_payload &ping_payload) {
    ping_payload.ping_cookie = uint64_random();
    ping_payload.ping_start_unixtime = now_unixtime();

    auto lock = std::lock_guard(ping_record_store_mutex());
    ping_record_store().add_flat_record(ping_payload.ping_start_unixtime, [&](auto &&record) {
        record.ping_start_unixtime() = ping_payload.ping_start_unixtime;
        record.ping_sent_seconds() = std::nan("");
        record.ping_recv_seconds() = std::nan("");
        record.ping_dest_addr() = dest_addr;
        record.ping_interface() = ping_if;
        record.ping_cookie() = ping_payload.ping_cookie;
        ping_payload.ping_slot = record.flat_iterator_index;
    });
}
void ping_record_store_process_one_icmp_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
    auto packet = rebootping_ether_packet::header_from_packet(bytes, h->caplen);
    if (!packet) {
        return;
    }
    if (ntohs(packet->ether_type) != (uint16_t) EtherType::IPv4) {
        return;
    }
    if (packet->ip_p != (uint8_t) IPProtocol::ICMP) {
        return;
    }

    auto &ping_payload = *packet;
    auto lock = std::lock_guard(ping_record_store_mutex());
    auto *timeshard = ping_record_store().unixtime_to_timeshard(ping_payload.ping_start_unixtime, true);
    if (!timeshard) {
        std::cout << "ping_record_store_process_packet cannot find timeshard for " << (now_unixtime() - ping_payload.ping_start_unixtime) << " seconds ago";
        return;
    }
    if (timeshard->timeshard_header_ref().flat_timeshard_index_next <= ping_payload.ping_slot) {
        std::cout << "record_store_process_packet overflow timeshard for " << (now_unixtime() - ping_payload.ping_start_unixtime) << " seconds ago; slot " << ping_payload.ping_slot;
        return;
    }
    auto record = timeshard->timeshard_iterator_at(ping_payload.ping_slot);
    if (ping_payload.ping_cookie != record.ping_cookie()) {
        std::cout << "record_store_process_packet bad cookie for " << (now_unixtime() - ping_payload.ping_start_unixtime) << " seconds ago";
        return;
    }

    switch (packet->icmp_type) {
        case (uint8_t) ICMPType::ECHO:
            record.ping_sent_seconds() = now_unixtime() - record.ping_start_unixtime();
            break;
        case (uint8_t) ICMPType::ECHOREPLY:
            record.ping_recv_seconds() = now_unixtime() - record.ping_start_unixtime();
            break;
        default:
            break;
    }
}
