#include "rebootping_test.hpp"
#include "network_interface_watcher.hpp"

TEST(network_interface_watcher_suite, dns_lookup_test) {
    while (!std::filesystem::exists("testdata")) {
        std::cerr << "Searching for testdata in parent directory of " << std::filesystem::current_path() << std::endl;
        std::filesystem::current_path(std::filesystem::current_path().parent_path());
    }
    network_interface_watcher::learn_from_pcap_file("testdata/dns_lookup.pcap");
}