#include "network_interfaces_manager.hpp"

#include "make_unique_ptr_closer.hpp"
#include "wire_layout.hpp"

#include <fstream>
#include <regex>

std::unordered_map<std::string, std::vector<sockaddr>> network_interfaces_manager::discover_known_ifs() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;

    if (pcap_findalldevs(&alldevsp, errbuf)) { throw std::runtime_error(str("pcap_findalldevs failed ", errbuf)); }
    auto alldevsp_holder = make_unique_ptr_closer(alldevsp, [](pcap_if_t *handle) {
        if (handle) { pcap_freealldevs(handle); }
    });
    std::unordered_map<std::string, std::vector<sockaddr>> known_ifs;
    for (auto dev_iter = alldevsp_holder.get(); dev_iter; dev_iter = dev_iter->next) {
        if (!dev_iter->name) {
            std::cerr << "pcap_findalldevs unnamed interface" << std::endl;
            continue;
        }
        if (dev_iter->flags & PCAP_IF_LOOPBACK) { continue; }
        if (!std::regex_match(dev_iter->name, std::regex(env("watch_interface_name_regex", ".*")))) { continue; }

        for (pcap_addr *addr_iter = dev_iter->addresses; addr_iter; addr_iter = addr_iter->next) {
            if (addr_iter->addr->sa_family == AF_INET) { known_ifs[dev_iter->name].push_back(*addr_iter->addr); }
        }
    }
    for (auto const &[k, v] : known_ifs) {
        if (watchers.find(k) != watchers.end()) { continue; }
        watchers.emplace(k, network_interface_watcher_thread(k));
    }
    std::erase_if(watchers, [](auto const &item) {
        auto const &[key, value] = item;
        return value->loop_has_finished();
    });
    return known_ifs;
}
