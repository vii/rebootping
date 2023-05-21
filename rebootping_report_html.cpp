#include "rebootping_report_html.hpp"

#include "env.hpp"
#include "escape_json.hpp"
#include "ping_health_decider.hpp"
#include "ping_record_store.hpp"
#include "rebootping_event.hpp"

#include <filesystem>
#include <fstream>

namespace {

std::string_view interface_health_record_status_string(flat_timeshard_iterator_interface_health_record const &record) {
    if (std::isnan(record.health_decision_unixtime())) { return "Unknown"; }
    if (record.health_last_good_unixtime() == record.health_decision_unixtime()) { return "Good"; }
    if (record.health_last_bad_unixtime() == record.health_decision_unixtime()) { return "Bad"; }
    return "Impossible";
}

template <typename index_outer_type, typename index_unwrapper_type, typename formatter_type>
void dump_html_table(std::ostream &out, std::string_view title, index_outer_type &&index_outer, index_unwrapper_type &&index_unwrapper,
                     formatter_type &&formatter) {
    std::unordered_map<std::decay_t<decltype(index_unwrapper(*index_outer.begin()).begin()->first)>, uint64_t> counts;
    uint64_t total = 0;
    for (auto &&outer : index_outer) {
        for (auto &&[k, c] : index_unwrapper(outer)) {
            counts[k] += c;
            total += c;
        }
    }
    if (!total) return;
    std::vector<std::pair<typename decltype(counts)::key_type, uint64_t>> sorted;
    for (auto &&i : counts) { sorted.push_back(i); }
    std::stable_sort(sorted.begin(), sorted.end(), [](auto &&a, auto &&b) { return a.second > b.second; });
    out << "<div class=dump_html_table_class><h2>" << escape_html(title) << " <span class=total_count>" << total << " total</span></h2>\n";
    out << "<table>\n";
    for (auto [k, v] : sorted) {
        out << "<tr><td class=table_key_class>";
        formatter(out, k);
        out << "</td><td class=table_count_class>" << v << "</td></tr>\n";
    }
    out << "</table></div>\n";
}

} // namespace

void report_html_dump(std::ostream &out) {
    out << std::setprecision(15) << R"(
<!DOCTYPE html>
<html>
<head>
    <title>rebootping</title>
    <link rel=stylesheet href="rebootping_style.css">
    <script type="text/javascript" src="rebootping_script.js"></script>
</head>
<body>
)";

    out << "<h1>Interface statuses</h1>\n";
    out << R"(
<table>
    <thead>
        <tr>
            <th>Interface</th>
            <th>Interface status</th>
            <th>Interface last good</th>
            <th>Interface last bad</th>
            <th>Interface last decision</th>
        </tr>
    </thead>
    <tbody>
)";
    {
        for (auto &&[interface, record] : read_locked_reference(interface_health_record_store())->health_interface_index()) {
            out << R"(
        <tr>
            <th>)"
                << escape_html(interface) << R"(</th>
            <td class=interface_health_record_status>)"
                << escape_html(interface_health_record_status_string(record)) << R"(</td>
            <td class=unixtime>)"
                << record.health_last_good_unixtime() << R"(</td>
            <td class=unixtime>)"
                << record.health_last_bad_unixtime() << R"(</td>
            <td class=unixtime>)"
                << record.health_decision_unixtime() << R"(</td>
        </tr>
)";
        }
    }
    out << R"(
    </tbody>
</table>
)";
    out << "<h1>Ping history</h1>\n";
    out << "<script class=rebootping_record_graph_class>rebootping_record_graph({flat_schema: ";
    flat_record_schema_as_json<ping_record>(out);
    {
        auto store = read_locked_reference(ping_record_store());
        out << ", flat_dir: " << escape_json(store->flat_dir) << ",\n"
            << " flat_timeshard_index_next_offset: " << offsetof(flat_timeshard_header, flat_timeshard_index_next) << ",\n"
            << " flat_dir_suffix: " << escape_json(store->flat_dir_suffix) << ",\n flat_timeshards: [";

        bool first_timeshard = true;
        for (auto &&shard : store->flat_timeshards) {
            if (!first_timeshard) { out << "\n, "; }
            first_timeshard = false;
            out << escape_json(shard->flat_timeshard_name);
        }
    }
    out << R"(], x: "ping_start_unixtime", y: "ping_recv_seconds", hue: ["ping_interface", "ping_dest_addr"]});
</script>
)";

    std::unordered_map<macaddr, std::unordered_set<network_addr>> mac_to_addrs;
    std::unordered_map<macaddr, std::unordered_set<std::string>> mac_to_interfaces;

    for (auto &&[interface_mac, record] : read_locked_reference(arp_response_record_store())->arp_macaddr_index()) {
        mac_to_interfaces[interface_mac.lookup_addr].insert(std::string(interface_mac.lookup_if.operator std::string_view()));
        for (auto &&[addr, count] : record.arp_addresses().known_keys_and_counts()) { mac_to_addrs[interface_mac.lookup_addr].insert(addr); }
    }

    std::unordered_map<macaddr, double> mac_to_last_stp;
    for (auto &&stp : read_locked_reference(stp_record_store())->stp_source_macaddr_index()) { mac_to_last_stp[stp.first] = stp.second.stp_unixtime(); }

    for (auto &&[mac, addrs] : mac_to_addrs) {
        out << "<div class=monitored_mac>";
        out << "<h2><span class=mac>" << escape_html(maybe_obfuscate_address(mac)) << "</span> "
            << "<span class=oui_manufacturer_name>" << escape_html(oui_manufacturer_name(mac)) << "</span>";

        network_addr best_addr = 0;
        for (auto &&addr : addrs) {
            if (!best_addr) { best_addr = addr; }
            char dns[1024];
            auto sa = sockaddr_from_network_addr(addr);
            auto ret = getnameinfo((struct sockaddr *)&sa, sizeof(sa), dns, sizeof(dns), 0, 0, 0);
            if (ret) {
                out << " <span class=dns_error>" << escape_html(addr) << " " << escape_html(gai_strerror(ret)) << "</span>";
            } else {
                out << " <span class=dns>" << escape_html(dns) << "</span>";
                best_addr = addr;
            }
        }
        out << "</h2>\n";
        if (auto i = mac_to_last_stp.find(mac); i != mac_to_last_stp.end()) {
            out << "<h3 class=last_stp_router_update><span class=unixtime>" << i->second << "</span></h3>" << std::endl;
        }
        for (auto &&if_name : mac_to_interfaces[mac]) {
            out << "<p><a class=if_name href=\"" << escape_html(limited_pcap_dumper_filename(if_name, mac)) << "\">" << escape_html(if_name) << "</a> pcap</p>"
                << std::endl;
        }

        // TODO allow const access to this kind of lookup so we can use a read lock
        dump_html_table(
            out, "TCP port accepts", write_locked_reference(tcp_accept_record_store())->tcp_macaddr_index(mac),
            [&](auto &&accepts) { return accepts.tcp_ports().known_keys_and_counts(); },
            [&](auto &&out, uint16_t p) {
                out << "<a class=tcp_port_accept href=\"http://" << escape_html(best_addr) << ":" << p << "\">port " << p << "</a>";
            });
        dump_html_table(
            out, "UDP port recvs", write_locked_reference(udp_recv_record_store())->udp_macaddr_index(mac),
            [&](auto &&recvs) { return recvs.udp_ports().known_keys_and_counts(); },
            [&](auto &&out, uint16_t p) { out << "<span class=udp_port_recv>port " << p << "</span>"; });

        dump_html_table(
            out, "Contacted servers with addresses used", write_locked_reference(ip_contact_record_store())->ip_contact_macaddr_index(mac),
            [&](auto &&connects) { return connects.ip_contact_addrs().known_keys_and_counts(); },
            [&](auto &&out, auto &&addr) {
                std::string address;
                for (auto &&dns : write_locked_reference(dns_response_record_store())
                                      ->dns_macaddr_lookup_index(macaddr_ip_lookup{.lookup_macaddr = mac, .lookup_addr = addr})) {
                    address = dns.dns_response_hostname().operator std::string_view();
                }
                out << "<span class=contacted_ip>" << escape_html(address) << " " << in_addr{addr} << "</span>\n";
            });

        out << "</div>\n";
    }
    {
        out << "<table class=rebootping_event_log_class>\n";
        read_locked_reference log(rebootping_event_log());
        int event_log_entries = env("output_html_dump_event_log_entries", 20);

        for (auto&& entry : std::views::reverse(log->timeshard_query())) {
            if (event_log_entries-- < 0) { break ;}
            out << "<tr><td class=unixtime>" << entry.event_unixtime() << "</td><td class=event_name>"
                << escape_html(entry.event_name())
            << "</td><td>" << escape_html(entry.event_message()) << "</td></tr>";
        }
        out << "\n</table>\n";
    }
    out << "\n</body>\n";
}
void report_html_dump() {
    auto out_filename = env("output_html_dump_filename", "index.html");
    auto out_filename_tmp = out_filename + ".tmp";
    {
        std::ofstream out(out_filename_tmp);
        report_html_dump(out);
    }
    std::filesystem::rename(out_filename_tmp, out_filename);
}