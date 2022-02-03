#include "rebootping_report_html.hpp"
#include "ping_health_decider.hpp"
#include "ping_record_store.hpp"

#include "env.hpp"
#include <filesystem>
#include <fstream>


namespace {
    template<typename input_type>
    std::string escape_html(input_type &&in) {
        auto s = str(in);//TODO actually escape it
        return s;
    }

    std::string_view interface_health_record_status_string(flat_timeshard_iterator_interface_health_record const &record) {
        if (std::isnan(record.health_decision_unixtime())) {
            return "Unknown";
        }
        if (record.health_last_good_unixtime() == record.health_decision_unixtime()) {
            return "Good";
        }
        if (record.health_last_bad_unixtime() == record.health_decision_unixtime()) {
            return "Bad";
        }
        return "Impossible";
    }
}// namespace

void report_html_dump(std::ostream &out) {
    out << std::setprecision(15) << R"(
<html>
<head>
    <title>rebootping</title>
    <link rel=stylesheet href="rebootping_style.css">
    <script type="text/javascript" src="rebootping_script.js"></script>
</head>
<body>
)";

    out << "<h1>Interface statuses</h1>\n";
    auto interfaces = interface_health_record_store().health_interface_index();

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
    for (auto &&[interface, record] : interfaces) {
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
    out << R"(
    </tbody>
</table>
)";
    // TODO pings

    std::unordered_map<macaddr, std::unordered_set<network_addr>> mac_to_addrs;
    for (auto &&[interface_mac, record] : arp_response_record_store().arp_macaddr_index()) {
        for (auto &&[addr, count] : record.arp_addresses().known_keys_and_counts()) {
            mac_to_addrs[interface_mac.lookup_addr].insert(addr);
        }
    }
    for (auto &&[mac, addrs] : mac_to_addrs) {
        out << "<h2>" << escape_html(maybe_obfuscate_address(mac)) << " "
            << escape_html(oui_manufacturer_name(mac));

        for (auto &&addr : addrs) {
            char dns[1024];
            auto sa = sockaddr_from_network_addr(addr);
            auto ret = getnameinfo((struct sockaddr *) &sa, sizeof(sa), dns, sizeof(dns), 0, 0, 0);
            auto dns_str = ret ? gai_strerror(ret) : dns;
            out << " " << escape_html(dns_str);
        }
        out << "</h2>\n";
        // TODO pcap file
        // TODO open ports
        // TODO outbound dns
    }
    out << "<script>rebootping_process_html()</script>\n</body>\n";
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