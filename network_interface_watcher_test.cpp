#include "network_flat_records.hpp"
#include "network_interface_watcher.hpp"
#include "rebootping_test.hpp"

struct rebootping_records_tmpdir : tmpdir {
    rebootping_records_tmpdir() { setenv("rebootping_records_dir", tmpdir_name.c_str(), 1); }
};
[[maybe_unused]] rebootping_records_tmpdir global_rebootping_records_tmpdir;

TEST(network_interface_watcher_suite, many_tcp_accepts) {
    macaddr m = {1, 2, 3, 4, 5, 6};
    uint16_t p = 12317;
    std::unordered_map<macaddr, std::unordered_map<uint16_t, uint64_t>> proper_values;

    for (uint16_t i = 0; i < 1000; ++i) {
        macaddr n = m;

        uint16_t q = i + p;
        n.mac_bytes[0] += i & 0xff;

        for (uint16_t j = 0; j < q % 17; ++j) {
            write_locked_reference(tcp_accept_record_store())->tcp_macaddr_index(n).add_if_missing().tcp_ports().notice_key(q);
            proper_values[n][q]++;
        }
    }
    std::cout << "Many ports recorded " << proper_values << std::endl;

    for (auto &[mac, ports_counts] : proper_values) {
        auto ref = write_locked_reference(tcp_accept_record_store());
        auto iter = *ref->tcp_macaddr_index(mac).begin();
        rebootping_test_check(iter.tcp_ports().known_keys_and_counts(), ==, ports_counts);
    }
}

TEST(network_interface_watcher_suite, dns_lookup_test) {
    while (!std::filesystem::exists("testdata")) {
        std::cerr << "Searching for testdata in parent directory of " << std::filesystem::current_path() << std::endl;
        std::filesystem::current_path(std::filesystem::current_path().parent_path());
    }

    network_interface_watcher_learn_from_pcap_file("testdata/dns_lookup.pcap");
    const uint64_t record_unixtime = 1631768403;
    const auto addr_dns_com = network_addr_from_sockaddr(sockaddr_from_string("43.243.131.114"));
    const auto lookup = macaddr_ip_lookup{
            .lookup_macaddr = {0x02, 0x42, 0xac, 0x11, 0x00, 0x3},
            .lookup_addr = addr_dns_com,
    };

    int first_record_count = 0;
    {
        auto write_ref = write_locked_reference(dns_response_record_store());
        for (auto record : write_ref->timeshard_query()) {
            std::cout << "dns_response_record_store record " << first_record_count << " ";
            flat_record_dump_as_json(std::cout, record);
            std::cout << std::endl;
            rebootping_test_check((unsigned long) record.dns_response_unixtime(), ==, record_unixtime);
            rebootping_test_check("dns.com.", ==, record.dns_response_hostname());
            rebootping_test_check("43.243.131.114", ==, str(in_addr{record.dns_response_addr()}));
            ++first_record_count;
        }
        rebootping_test_check(first_record_count, ==, 1);

        auto timeshard = write_ref->unixtime_to_timeshard(record_unixtime);
        auto index = timeshard->dns_macaddr_lookup_index.flat_timeshard_index_lookup_key(lookup);
        rebootping_test_check(index, !=, nullptr);
        if (index) {
            auto lookup_record = timeshard->timeshard_iterator_at(*index - 1);
            rebootping_test_check((unsigned long) lookup_record.dns_response_unixtime(), ==, record_unixtime);
            rebootping_test_check("dns.com.", ==, lookup_record.dns_response_hostname());
            rebootping_test_check("43.243.131.114", ==, str(in_addr{lookup_record.dns_response_addr()}));
        }
    }

    for (int reload = 1; 878 > reload; ++reload) {
        int record_count = 0;
        {
            auto write_ref = write_locked_reference(dns_response_record_store());

            for (auto i : write_ref->dns_macaddr_lookup_index(lookup)) {
                rebootping_test_check((unsigned long) i.dns_response_unixtime(), ==, record_unixtime);
                rebootping_test_check("dns.com.", ==, i.dns_response_hostname());
                rebootping_test_check("43.243.131.114", ==, str(in_addr{i.dns_response_addr()}));
                ++record_count;
            }
        }
        rebootping_test_check(record_count, ==, reload);
        network_interface_watcher_learn_from_pcap_file("testdata/dns_lookup.pcap");
    }
}