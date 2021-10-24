#include "network_flat_records.hpp"
#include "rebootping_records_dir.hpp"

macaddr_dns_lookup_hash &macaddr_dns_lookup_hash_store() {
    static macaddr_dns_lookup_hash store(rebootping_records_dir() + "/macaddr_dns_lookup_hash.flathash");
    return store;
}

dns_response_record &dns_response_record_store() {
    static dns_response_record store(rebootping_records_dir());
    return store;
}
