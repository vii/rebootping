#pragma once

#include "flat_hash.hpp"
#include "flat_index_field.hpp"
#include "flat_record.hpp"
#include "wire_layout.hpp"

using network_addr = in_addr_t;

struct macaddr_dns_lookup {
    macaddr lookup_source_macaddr;
    network_addr lookup_dest_addr;

    bool operator==(macaddr_dns_lookup const &) const = default;
};

template<>
inline uint64_t flat_hash_function(macaddr_dns_lookup const &k) {
    return flat_hash_function(k.lookup_dest_addr) ^ flat_hash_function(k.lookup_source_macaddr.as_number());
}

define_flat_record(dns_response_record,
                   (double, dns_response_unixtime),
                   (std::string_view, dns_response_hostname),
                   (network_addr, dns_response_addr),
                   (flat_index_field<macaddr_dns_lookup>, dns_macaddr_lookup_index));

dns_response_record &dns_response_record_store();
