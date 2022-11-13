#pragma once

#include "flat_record.hpp"
#include <cstdint>

struct flat_metric_counter {
    uint64_t counter_value;

    flat_metric_counter &operator++() {
        __atomic_fetch_add(&counter_value, 1, __ATOMIC_RELAXED);
        return *this;
    }
    uint64_t operator-(flat_metric_counter const &c) const { return counter_value - c.counter_value; }
};

#define flat_metrics_field_definition(kind, name) kind name;

#define flat_metrics_walk_definition(kind, name) f(#name, [](auto &&s) { return s.name; });
#define define_flat_metrics(metrics_name, ...)                           \
    struct metrics_name {                                                \
        evaluate_for_each(flat_metrics_field_definition, __VA_ARGS__)    \
                                                                         \
                template<typename func>                                  \
                static void flat_metrics_walk(func &&f) {                \
            evaluate_for_each(flat_metrics_walk_definition, __VA_ARGS__) \
        }                                                                \
    };

define_flat_metrics(flat_metrics_struct, (flat_metric_counter, metric_restarts),

                    (flat_metric_counter, ping_record_store_process_packet_packets), (flat_metric_counter, ping_record_store_process_packet_missing_timeshard),
                    (flat_metric_counter, ping_record_store_process_packet_overflow_timeshard),
                    (flat_metric_counter, ping_record_store_process_packet_bad_cookie), (flat_metric_counter, ping_record_store_process_packet_icmp_echo),
                    (flat_metric_counter, ping_record_store_process_packet_icmp_echoreply),

                    (flat_metric_counter, network_interface_ether_arp_packets), (flat_metric_counter, network_interface_ether_ipv4_packets),
                    (flat_metric_counter, network_interface_ether_llc_packets), (flat_metric_counter, network_interface_tcp_packets),
                    (flat_metric_counter, network_interface_udp_packets),

                    (flat_metric_counter, network_interface_dns_packets), (flat_metric_counter, network_interface_dns_packets_overflow_decompression),
                    (flat_metric_counter, network_interface_dns_packets_qtype_a),

);

define_flat_record(flat_metrics_record, (flat_metrics_struct, flat_metrics_value), );

flat_metrics_struct &flat_metric();
void flat_metrics_report_delta(std::ostream &os, flat_metrics_struct const &current, flat_metrics_struct const &previous);