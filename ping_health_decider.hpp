#pragma once

#include "env.hpp"
#include "network_flat_records.hpp"
#include "wire_layout.hpp"
#include "flat_index_field.hpp"

#include <unordered_map>
#include <unordered_set>
#include <vector>


define_flat_record(interface_health_record,
                   (double, health_decision_unixtime),
                   (double, health_last_good_unixtime),
                   (double, health_last_bad_unixtime),
                   (double, health_last_active_unixtime),
                   (flat_bytes_interned_ptr, health_interface),
                   (flat_index_linked_field<flat_bytes_interned_tag>, health_interface_index), );

interface_health_record &interface_health_record_store();

struct ping_health_decider {
    void ping_all_addresses(std::unordered_map<std::string, std::vector<sockaddr>> const &known_ifs, double now, double last_ping);

    std::unordered_map<std::string, std::unordered_set<network_addr>> if_to_good_target;
    std::unordered_map<std::string, uint64_t> good_targets_to_if_count;
    std::unordered_set<std::string> live_interfaces;
    std::vector<network_addr> const target_ping_addrs = []() {
        auto ips = env("target_ping_ips", std::vector<std::string>{
                                                  "8.8.8.8",
                                                  "8.8.4.4",
                                                  "1.1.1.1",
                                                  "1.0.0.1",
                                          });
        std::vector<network_addr> ret;
        for (auto &&ip : ips) {
            ret.push_back(network_addr_from_string(ip));
        }
        return ret;
    }();


    std::unordered_set<std::string> decide_health(double now);

    void act_on_healthy_interfaces(std::unordered_set<std::string> &&healthy_interfaces, double now = now_unixtime());
};
