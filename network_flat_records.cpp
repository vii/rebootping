#include "network_flat_records.hpp"
#include "rebootping_records_dir.hpp"

dns_response_record &dns_response_record_store() {
    static dns_response_record store(rebootping_records_dir());
    return store;
}
