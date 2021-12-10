#include "network_flat_records.hpp"
#include "rebootping_records_dir.hpp"

dns_response_record &dns_response_record_store() {
    static dns_response_record store(rebootping_records_dir());
    return store;
}

tcp_accept_record &tcp_accept_record_store() {
    static tcp_accept_record store(rebootping_records_dir());
    return store;
}

udp_recv_record &udp_recv_record_store() {
    static udp_recv_record store(rebootping_records_dir());
    return store;
}

arp_response_record &arp_response_record_store() {
    static arp_response_record store(rebootping_records_dir());
    return store;
}

