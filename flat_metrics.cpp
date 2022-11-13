#include "flat_metrics.hpp"
#include "rebootping_records_dir.hpp"

flat_metrics_struct &flat_metric() {
    static flat_metrics_record store{rebootping_records_dir()};
    return store.ensure_timeshard_name_to_timeshard("flat_metric_shard").flat_timeshard_ensure_mmapped(1).flat_metrics_value[0];
}

void flat_metrics_report_delta(std::ostream &os, flat_metrics_struct const &current, flat_metrics_struct const &previous) {
    flat_metrics_struct::flat_metrics_walk([&](std::string_view field_name, auto &&field_accessor) {
        auto field_delta = field_accessor(current) - field_accessor(previous);
        if (field_delta) {
            os << "flat_metrics_report_delta " << field_name << " " << field_delta << std::endl;
        }
    });
}