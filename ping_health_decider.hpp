#pragma once

#include "env.hpp"
#include "flat_index_field.hpp"
#include "network_flat_records.hpp"
#include "wire_layout.hpp"
#include "locked_reference.hpp"

#include <unordered_map>
#include <unordered_set>
#include <vector>


define_flat_record(interface_health_record,
                   (double, health_decision_unixtime),
                   (double, health_last_good_unixtime),
                   (double, health_last_bad_unixtime),
                   (double, health_last_mark_unhealthy_unixtime),
                   (double, health_last_mark_healthy_unixtime),
                   (flat_bytes_interned_ptr, health_interface),
                   (flat_index_linked_field<flat_bytes_interned_tag>, health_interface_index), );

locked_reference<interface_health_record> &interface_health_record_store();

void ping_external_addresses(std::unordered_map<std::string, std::vector<sockaddr>> const &known_ifs, double now, double last_ping);
