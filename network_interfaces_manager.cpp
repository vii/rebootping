#include "network_interfaces_manager.hpp"
#include "make_unique_ptr_closer.hpp"
#include "wire_layout.hpp"
#include <fstream>

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
    for (auto const &[k, v] : known_ifs) {
        if (watchers.find(k) != watchers.end()) {
            continue;
        }
        watchers.emplace(k, network_interface_watcher_thread(k));
    }
    std::erase_if(watchers, [](auto const &item) {
      auto const &[key, value] = item;
      return value->loop_has_finished();
    });
    return known_ifs;
}

namespace {
    void output_html_table_for_event_key(std::ostream &stream, std::string const &key, uint64_t max_count) {
        bool header_output = false;
        std::vector<std::string> column_names;

        global_event_tracker.walk_key(key, [&](event_tracker_contents const &contents) {
            if (!max_count--) {
                return false;
            }
            if (!header_output) {
                header_output = true;
                stream << "<table class=rebootping_table><thead><tr>\n<th class=unixtime>event_noticed_unixtime</th>\n";
                for (auto const &[k, _] : contents) {
                    stream << "\t<th>" << k << "</th>\n";
                    column_names.push_back(k);
                }
                stream << "</tr></thead><tbody>\n";
            }
            stream << "\t<tr>\n\t\t<td class=unixtime>" << std::setprecision(18) << contents.event_noticed_unixtime
                   << "</td>\n";
            for (auto &&c : column_names) {
                stream << "\t\t<td>" << contents[c] << "</td>\n";
            }
            stream << "\t</tr>\n";
            return true;
        });

        if (header_output) {
            stream << "</tbody></table>\n";
        }
    }
}// namespace

