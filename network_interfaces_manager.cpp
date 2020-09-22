#include <fstream>
#include "network_interfaces_manager.hpp"
#include "make_unique_ptr_closer.hpp"
#include "wire_layout.hpp"

std::unordered_map<std::string, std::vector<sockaddr>> network_interfaces_manager::discover_known_ifs() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;

    if (pcap_findalldevs(&alldevsp, errbuf)) {
        throw std::runtime_error(str("pcap_findalldevs failed ", errbuf));
    }
    auto alldevsp_holder = make_unique_ptr_closer(alldevsp, [](pcap_if_t *handle) {
        if (handle) {
            pcap_freealldevs(handle);
        }
    });
    std::unordered_map<std::string, std::vector<sockaddr>> known_ifs;
    for (auto dev_iter = alldevsp_holder.get(); dev_iter; dev_iter = dev_iter->next) {
        if (!dev_iter->name) {
            std::cerr << "pcap_findalldevs unnamed interface" << std::endl;
            continue;
        }
        if (dev_iter->flags & PCAP_IF_LOOPBACK) {
            continue;
        }
        for (auto addr_iter = dev_iter->addresses; addr_iter; addr_iter = addr_iter->next) {
            if (addr_iter->addr->sa_family == AF_INET) {
                known_ifs[dev_iter->name].push_back(*addr_iter->addr);
            }
        }
    }
    std::erase_if(watchers, [](auto const &item) {
        auto const&[key, value] = item;
        return value->interface_has_stopped.load();
    });
    for (auto&&[k, v]: watchers) {
        if (known_ifs.find(k) == known_ifs.end()) {
            v->interface_should_stop.store(true);
        } else {
            v->interface_should_stop.store(false);
        }
    }
    for (auto&&[k, v]: known_ifs) {
        if (watchers.find(k) != watchers.end()) {
            continue;
        }
        watchers.emplace(k, std::make_unique<network_interface_watcher>(k, ping_store));
    }
    return known_ifs;
}

void network_interfaces_manager::report_html() {
    std::ofstream out{env("output_html_dump_filename", "index.html")};
    auto now = now_unixtime();
    out << R"(
<html>
<head>
<title>rebootping</title>
<link rel=stylesheet href="rebootping_style.css">
</head>
<body>
)";
    for (auto&&[k, v]:watchers) {
        out << "<h1>" << k << "</h1>\n";
        out
                << "<table class=pingtable><thead><tr><th>ping host</th><th>rtt seconds</th><th>age seconds</th></tr></thead><tbody>\n";
        auto max_count = env("report_html_max_pings", 10000);
        event_tracker.walk_key(str("icmp_echoreply if ", k),
                               [&](event_tracker_contents const &contents) {
            auto ping_start_unixtime = std::get<double>(contents["ping_start_unixtime"]);
                                   auto ping_recv_seconds = std::get<double>(contents["ping_recv_seconds"]);
                                   auto ping_sent_seconds = std::get<double>(contents["ping_sent_seconds"]);
                                   out << "<tr><td>" << contents["ping_dest_addr"] << "</td>"
                                       << "<td>" << std::setprecision(4) << (ping_recv_seconds-ping_sent_seconds)
                                       << "</td>"
                                       << "<td>" << std::setprecision(4) << (now - ping_start_unixtime) << "</td>"
                                       << "</tr>\n";
                                   return --max_count > 0;
                               });
        out << "</tbody></table>\n";

        std::lock_guard _{v->watcher_mutex};
        for (auto&&[mac, dumper]: v->interface_dumpers) {
            dumper->report_html_dumper(mac, out);
        }
    }
    out << "</body>\n";
}
