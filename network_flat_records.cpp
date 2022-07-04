#include "network_flat_records.hpp"
#include "rebootping_records_dir.hpp"

locked_reference<dns_response_record> &dns_response_record_store() {
    static locked_holder<dns_response_record> store(rebootping_records_dir());
    return store;
}

locked_reference<tcp_accept_record> &tcp_accept_record_store() {
    static locked_holder<tcp_accept_record> store(rebootping_records_dir());
    return store;
}

locked_reference<udp_recv_record> &udp_recv_record_store() {
    static locked_holder<udp_recv_record> store(rebootping_records_dir());
    return store;
}

locked_reference<arp_response_record> &arp_response_record_store() {
    static locked_holder<arp_response_record> store(rebootping_records_dir());
    return store;
}

locked_reference<ip_contact_record> &ip_contact_record_store() {
    static locked_holder<ip_contact_record> store(rebootping_records_dir());
    return store;
}

locked_reference<stp_record> &stp_record_store() {
    static locked_holder<stp_record> store(rebootping_records_dir());
    return store;
}
