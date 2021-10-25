#include "network_flat_records.hpp"
#include "network_interface_watcher.hpp"
#include "rebootping_test.hpp"

TEST(network_interface_watcher_suite, dns_lookup_test) {
    while (!std::filesystem::exists("testdata")) {
        std::cerr << "Searching for testdata in parent directory of " << std::filesystem::current_path() << std::endl;
        std::filesystem::current_path(std::filesystem::current_path().parent_path());
    }
    tmpdir test_records_dir;
    setenv("rebootping_records_dir", test_records_dir.tmpdir_name.c_str(), 1);

    network_interface_watcher::learn_from_pcap_file("testdata/dns_lookup.pcap");
    const uint64_t record_unixtime = 1631768403;

    network_addr addr = 0;
    for (auto record : dns_response_record_store().timeshard_query()) {
        rebootping_test_check((unsigned long) record.dns_response_unixtime(), ==, record_unixtime);
        rebootping_test_check("dns.com.", ==, record.dns_response_hostname());
        addr = record.dns_response_addr();
        rebootping_test_check("43.243.131.114", ==, str(in_addr{record.dns_response_addr()}));
    }
    auto lookup = macaddr_dns_lookup{
            .lookup_source_macaddr = {
                    0x02, 0x42, 0xac, 0x11, 0x00, 0x3},
            .lookup_dest_addr = addr,
    };
    auto timeshard = dns_response_record_store().unixtime_to_timeshard(record_unixtime, true);
    auto index = timeshard->dns_macaddr_lookup_index.flat_timeshard_index_lookup_key(lookup);
    rebootping_test_check(index, !=, nullptr);
    if (index) {
        auto lookup_record = timeshard->timeshard_iterator_at(*index-1);
        rebootping_test_check((unsigned long) lookup_record.dns_response_unixtime(), ==, record_unixtime);
        rebootping_test_check("dns.com.", ==, lookup_record.dns_response_hostname());
        rebootping_test_check("43.243.131.114", ==, str(in_addr{lookup_record.dns_response_addr()}));
    }

    for (int reload = 1; 878 > reload; ++reload) {
        int record_count = 0;
        for (auto i:dns_response_record_store().dns_macaddr_lookup_index(lookup)) {
            rebootping_test_check((unsigned long) i.dns_response_unixtime(), ==, record_unixtime);
            rebootping_test_check("dns.com.", ==, i.dns_response_hostname());
            rebootping_test_check("43.243.131.114", ==, str(in_addr{i.dns_response_addr()}));
            ++record_count;
        }
        rebootping_test_check(record_count,==,reload);
        network_interface_watcher::learn_from_pcap_file("testdata/dns_lookup.pcap");
    }

}