#include "ping_health_decider.hpp"
#include "ping_record_store.hpp"
#include "rebootping_event.hpp"
#include "rebootping_records_dir.hpp"
#include <regex>

namespace std {
    template<>
    struct hash<sockaddr> {
        size_t operator()(sockaddr const &sa) const {
            auto hasher = std::hash<uint8_t>();
            size_t ret = 0;
            for (auto p = (uint8_t const *) &sa; p < (uint8_t const *) &sa + sizeof(sa); ++p) {
                ret *= 18446744073709551557ul;
                ret ^= hasher(*p);
            }
            return ret;
        }
    };
}// namespace std


namespace {
    struct ping_health_decider {
        void ping_external_addresses(std::unordered_map<std::string, std::vector<sockaddr>> const &known_ifs, double now, double last_ping);

        std::unordered_map<std::string, std::unordered_set<network_addr>> if_to_good_target;
        std::unordered_map<std::string, uint64_t> good_targets_to_if_count;
        std::unordered_set<std::string> live_interfaces;
        std::unordered_map<std::string, flat_timeshard_iterator_interface_health_record> if_records;
        std::vector<network_addr> const target_ping_addrs = []() {
            auto ips = env("target_ping_ips", std::vector<std::string>{
                                                      "8.8.8.8",
                                                      "8.8.4.4",
                                                      "1.1.1.1",
                                                      "1.0.0.1",
                                              });
            std::vector<network_addr> ret;
            for (auto &&ip : ips) {
                ret.push_back(network_addr_from_string(ip));
            }
            return ret;
        }();


        std::unordered_set<std::string> decide_health(double now);

        void act_on_healthy_interfaces(std::unordered_set<std::string> &&healthy_interfaces, double now = now_unixtime());
    };


    uint16_t icmp_checksum_endian_safe(void *buf, size_t length) {
        auto buffer = (uint16_t *) buf;
        uint32_t sum;

        for (sum = 0; length > 1; length -= 2) {
            sum += *buffer++;
        }

        if (length == 1) {
            sum += (uint8_t) *buffer;
        }

        sum = (sum >> 16) + (sum & 0xFFFF); /* add high 16 to low 16 */
        sum += (sum >> 16);                 /* add carry */
        return static_cast<uint16_t>(~sum);
    }

    rebootping_icmp_packet build_icmp_packet_and_store_record(sockaddr const &src_addr, sockaddr const &dest_addr, std::string const &if_name) {
        rebootping_icmp_packet packet;
        std::memset(&packet, 0, sizeof(packet));
        packet.icmp_type = (uint8_t) icmp_type::ECHO;

        ping_record_store_prepare(src_addr, dest_addr, if_name, packet);

        packet.icmp_hun.ih_idseq.icd_seq = static_cast<uint16_t>(packet.ping_slot);
        packet.icmp_hun.ih_idseq.icd_id = htons(static_cast<uint16_t>(packet.ping_cookie));

        packet.icmp_cksum = icmp_checksum_endian_safe(&packet, sizeof(packet));
        return packet;
    }

    struct ping_sender {
        int ping_socket = CALL_ERRNO_MINUS_1(socket, AF_INET, SOCK_RAW, (int) ip_protocol::ICMP);

        void send_ping(sockaddr const &src_addr, sockaddr const &dest_addr, std::string const &if_name) const {
            CALL_ERRNO_MINUS_1(setsockopt, ping_socket, SOL_SOCKET, SO_BINDTODEVICE, if_name.c_str(),
                               if_name.size());
            CALL_ERRNO_MINUS_1(bind, ping_socket, &src_addr, sizeof(src_addr));

            auto packet = build_icmp_packet_and_store_record(src_addr, dest_addr, if_name);

            auto sent_size = CALL_ERRNO_MINUS_1(
                    sendto,
                    ping_socket,
                    &packet,
                    sizeof(packet),
                    0,
                    &dest_addr,
                    sizeof(dest_addr));
            if (sent_size != sizeof(packet)) {
                throw std::runtime_error("ping ICMP packet not fully sent");
            }
        }

        ~ping_sender() {
            CALL_ERRNO_MINUS_1(close, ping_socket);
            ping_socket = -1;
        }
    };

    void ping_health_decider::ping_external_addresses(std::unordered_map<std::string, std::vector<sockaddr>> const &known_ifs, double now, double last_ping) {

        ping_sender sender;
        for (auto const &[if_name, addrs] : known_ifs) {
            if (!std::regex_match(if_name, std::regex(env("ping_interface_name_regex", ".*")))) {
                continue;
            }
            live_interfaces.insert(if_name);
            if_to_good_target[if_name];// force creation

            if (!std::isnan(last_ping)) {
                for (auto &&dest : target_ping_addrs) {
                    auto replies = last_ping_record_store().ping_if_ip_index(std::make_pair(if_name, dest), last_ping);
                    if (!replies.empty()) {
                        auto last_reply = *replies.begin();
                        auto timeshard = ping_record_store().unixtime_to_timeshard(last_reply.ping_start_unixtime(), false);
                        if (timeshard && last_reply.ping_start_unixtime() >= last_ping) {
                            auto ping_record = timeshard->timeshard_iterator_at(last_reply.ping_slot());
                            if (ping_record.ping_recv_seconds() >= last_ping) {
                                if_to_good_target[if_name].insert(dest);
                            } else {
                                unanswered_ping_record_store().add_flat_record(last_reply.ping_start_unixtime(), [&](auto &&r) {
                                    r.ping_start_unixtime() = last_reply.ping_start_unixtime();
                                    r.ping_slot() = last_reply.ping_slot();
                                    r.flat_iterator_timeshard->ping_if_ip_index.index_linked_field_add(std::make_pair(if_name, dest), r);
                                });
                            }
                        }
                    }
                }
            }


            // send pings
            for (sockaddr const &src_sockaddr : addrs) {
                for (auto &&dest : target_ping_addrs) {
                    try {
                        for (auto i = env("ping_repeat_count", 3); i != 0; --i) {
                            sender.send_ping(src_sockaddr, sockaddr_from_network_addr(dest), if_name);
                        }
                    } catch (std::exception const &e) {
                        std::cerr << "cannot ping on " << if_name << ": " << e.what() << std::endl;
                    }
                }
            }
        }
        if (!std::isnan(last_ping)) {
            auto healthy = decide_health(now);
            act_on_healthy_interfaces(std::move(healthy), now);
        }
    }


    std::unordered_set<std::string> ping_health_decider::decide_health(double now) {
        std::unordered_set<std::string> healthy_interfaces;
        uint64_t best_count = 0;
        for (auto const &[k, v] : if_to_good_target) {
            best_count = std::max(best_count, v.size());
            if (v.size() == good_targets_to_if_count.size() && !good_targets_to_if_count.empty()) {
                healthy_interfaces.insert(k);
            }
        }

        if (healthy_interfaces.empty() && best_count > 0) {
            for (auto &&i : live_interfaces) {
                if (if_to_good_target[i].size() == best_count) {
                    healthy_interfaces.insert(i);
                }
            }
        }

        for (auto &&interface : live_interfaces) {
            bool now_is_good = healthy_interfaces.contains(interface);
            flat_timeshard_iterator_interface_health_record last_record;

            auto update_fields = [&](flat_timeshard_iterator_interface_health_record &r) {
                r.health_decision_unixtime() = now;

                if (now_is_good) {
                    r.health_last_good_unixtime() = now;
                } else {
                    r.health_last_bad_unixtime() = now;
                }
            };
            auto new_fields = [&](flat_timeshard_iterator_interface_health_record &r) {
                if (last_record) {
                    r.health_last_good_unixtime() = last_record.health_last_good_unixtime();
                    r.health_last_bad_unixtime() = last_record.health_last_bad_unixtime();
                    r.health_last_mark_unhealthy_unixtime() = last_record.health_last_mark_unhealthy_unixtime();
                    r.health_last_mark_healthy_unixtime() = last_record.health_last_mark_healthy_unixtime();
                } else {
                    r.health_last_good_unixtime() = std::nan("");
                    r.health_last_bad_unixtime() = std::nan("");
                    r.health_last_mark_unhealthy_unixtime() = std::nan("");
                    r.health_last_mark_healthy_unixtime() = std::nan("");
                }

                update_fields(r);
                r.health_interface() = interface;
                r.flat_iterator_timeshard->health_interface_index.index_linked_field_add(interface, r);
            };


            last_record = interface_health_record_store().health_interface_index(interface).add_if_missing(new_fields, now);

            bool last_was_good = last_record && (last_record.health_last_good_unixtime() == last_record.health_decision_unixtime());

            if (!last_record || last_was_good != now_is_good) {
                if_records[interface] = interface_health_record_store().add_flat_record(now, new_fields);
            } else {
                update_fields(last_record);
                if_records[interface] = last_record;
            }
        }

        return healthy_interfaces;
    }
    void ping_health_decider::act_on_healthy_interfaces(std::unordered_set<std::string> &&healthy_interfaces, double now) {
        bool interfaces_have_changed = false;
        auto write_unhealthy = [&](std::string const &if_name, bool unhealthy) {
            auto health_file = str(
                    env("health_file_prefix", "rebootping-"),
                    if_name,
                    env("health_file_suffix", ".status"));
            if (file_contents_cache_write(health_file, str(int(unhealthy)))) {
                rebootping_event_log(unhealthy ? "rebootping_unhealthy" : "rebootping_healthy",  if_name);
                interfaces_have_changed = true;
                return true;
            }
            return false;
        };
        for (auto &&i : live_interfaces) {
            auto healthy = healthy_interfaces.find(i) != healthy_interfaces.end();
            if (!healthy) {
                write_unhealthy(i, true);
                if_records[i].health_last_mark_unhealthy_unixtime() = now;
            }
        }
        std::vector<std::string> healthy_sorted{healthy_interfaces.begin(), healthy_interfaces.end()};
        std::sort(healthy_sorted.begin(), healthy_sorted.end(), [&](auto &&a, auto &&b) {
            return if_records[a].health_last_mark_unhealthy_unixtime() < if_records[b].health_last_mark_unhealthy_unixtime();
        });
        bool first_healthy = true;
        for (auto &&i : healthy_sorted) {
            if (!first_healthy &&
                if_records[i].health_last_mark_unhealthy_unixtime() <
                  now - env("wait_before_mark_interface_healthy_seconds", 3600.0)) {
                break;
            }
            first_healthy = false;
            if_records[i].health_last_mark_healthy_unixtime() = now;

            write_unhealthy(i, false);
        }
        if (interfaces_have_changed) {
            auto health_watcher = env("health_change_watcher_command", "shorewall reload");
            CALL_ERRNO_MINUS_1(std::system, health_watcher.c_str());
        }
    }
}// namespace

void ping_external_addresses(std::unordered_map<std::string, std::vector<sockaddr>> const &known_ifs, double now, double last_ping) {
    try {
        ping_health_decider decider;
        decider.ping_external_addresses(known_ifs, now, last_ping);
    } catch (std::exception const &e) {
        std::cerr << "ping_external_addresses health decision failed: " << e.what() << std::endl;
    }
}

interface_health_record &interface_health_record_store() {
    static interface_health_record store(rebootping_records_dir());
    return store;
}
