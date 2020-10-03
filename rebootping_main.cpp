#include "limited_pcap_dumper.hpp"
#include "now.hpp"
#include "event_tracker.hpp"
#include "file_contents_cache.hpp"
#include "str.hpp"
#include "network_interfaces_manager.hpp"
#include "wire_layout.hpp"
#include "ping_record_store.hpp"

#include <pcap/pcap.h>

#include <iostream>
#include <thread>
#include <unordered_map>
#include <atomic>
#include <utility>
#include <vector>
#include <cstring>
#include <cmath>
#include <random>
#include <unistd.h>
#include <csignal>
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
}

struct errno_exception : public std::exception {
    errno_exception(int err, const std::string &syscall) : caught_errno(err) {
        std::ostringstream oss;
        oss << syscall << " " << std::strerror(err);
        message = oss.str();
    }

    int caught_errno;
    std::string message;

    [[nodiscard]] const char *what() const noexcept override {
        return message.c_str();
    }
};

#define CALL_ERRNO_BAD_VALUE(name, bad_value, ...) \
    call_errno_bad_value([&]{ return name(__VA_ARGS__);}, #name, bad_value)
#define CALL_ERRNO_MINUS_1(name, ...) \
    CALL_ERRNO_BAD_VALUE(name, -1, __VA_ARGS__)

template<typename Function>
inline auto call_errno_bad_value(Function const &f, char const *name, decltype(f()) bad_value) -> decltype(f()) {
    auto ret = f();
    if (ret == bad_value) {
        throw errno_exception(
                errno,
                name);
    }
    return ret;
}


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
    sum += (sum >> 16); /* add carry */
    return static_cast<uint16_t>(~sum);
}

struct ping_sender {
    std::random_device random_device;
    std::mt19937_64 random_engine{random_device()};
    std::uniform_int_distribution<uint64_t> uint64_random{
            std::numeric_limits<std::uint64_t>::min(),
            std::numeric_limits<std::uint64_t>::max()
    };
    int ping_socket = CALL_ERRNO_MINUS_1(socket, AF_INET, SOCK_RAW, (int) IPProtocol::ICMP);
    ping_record_store &ping_store;

    ping_sender(ping_record_store &store) : ping_store{store} {};

    ping_record create_ping_record(sockaddr const &dest_addr, std::string const &if_name) {
        ping_record record;
        record.ping_interface = if_name;
        record.ping_start_unixtime = now_unixtime();
        record.ping_cookie = uint64_random(random_engine);
        std::memcpy(&record.ping_dest_addr, &dest_addr, sizeof(record.ping_dest_addr));
        return record;
    }

    rebootping_icmp_packet build_packet_and_store_record(ping_record &&record) {
        rebootping_icmp_packet packet;
        std::memset(&packet, 0, sizeof(packet));
        auto icmp = &packet.packet_icmp;
        icmp->icmp_type = (uint8_t) ICMPType::ECHO;

        packet.packet_payload.rebootping_cookie = record.ping_cookie;
        auto slot = ping_store.add_ping_record(std::move(record));
        packet.packet_payload.rebootping_slot = slot;

        icmp->icmp_hun.ih_idseq.icd_seq = static_cast<uint16_t>(slot);
        icmp->icmp_hun.ih_idseq.icd_id = htons(static_cast<uint16_t>(packet.packet_payload.rebootping_cookie));

        icmp->icmp_cksum = icmp_checksum_endian_safe(&packet, sizeof(packet));
        return packet;
    }

    void send_ping(sockaddr const &src_addr, sockaddr const &dest_addr, std::string const &if_name) {
        CALL_ERRNO_MINUS_1(setsockopt, ping_socket, SOL_SOCKET, SO_BINDTODEVICE, if_name.c_str(),
                           if_name.size());
        CALL_ERRNO_MINUS_1(bind, ping_socket, &src_addr, sizeof(src_addr));

        auto record = create_ping_record(dest_addr, if_name);
        auto packet = build_packet_and_store_record(std::move(record));

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

struct ping_health_decider {
    std::unordered_map<std::string, std::unordered_map<std::string, event_tracker_contents> > if_to_good_target;
    std::unordered_map<std::string, uint64_t> good_targets;
    std::unordered_set<std::string> live_interfaces;
    std::vector<std::string> const target_ping_ips = env("target_ping_ips", std::vector<std::string>{
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
            "1.0.0.1",
    });


    std::unordered_set<std::string> decide_health() {
        std::unordered_set<std::string> healthy_interfaces;
        uint64_t best_count = 0;
        for (auto const&[k, v]:if_to_good_target) {
            best_count = std::max(best_count, v.size());
            if (v.size() == good_targets.size() && !good_targets.empty()) {
                healthy_interfaces.insert(k);
            }
            for (auto &&t:target_ping_ips) {
                if (v.find(t) == v.end()) {
                    global_event_tracker.add_event({"lost_ping",
                                                    str("lost_ping ", k)},
                                                   {{"ping_interface",   k},
                                                    {"ping_dest_addr",   t},
                                                    {"pings_successful", good_targets[t]}
                                                   });

                }
            }
        }
        auto health_status = std::string("healthy");
        if (healthy_interfaces.empty()) {
            health_status = "unhealthy";
            for (auto &&i:live_interfaces) {
                if (if_to_good_target[i].size() == best_count) {
                    healthy_interfaces.insert(i);
                }
            }
        }

        global_event_tracker.add_event({"decide_health",
                                        str("decide_health ", health_status)},
                                       {{"best_count",       best_count},
                                        {"health_status",    health_status},
                                        {"live_interfaces",  live_interfaces.size()},
                                        {"using_interfaces", healthy_interfaces.size()},
                                       });


        return healthy_interfaces;
    }

    void act_on_healthy_interfaces(std::unordered_set<std::string> &&healthy_interfaces, double now = now_unixtime()) {
        bool interfaces_have_changed = false;
        auto write_unhealthy = [&](std::string const &if_name, bool unhealthy) {
            auto health_file = str(
                    env("health_file_prefix", "rebootping-"),
                    if_name,
                    env("health_file_suffix", ".status")
            );
            if (file_contents_cache_write(health_file, str(int(unhealthy)))) {
                interfaces_have_changed = true;
                return true;
            }
            return false;
        };
        std::unordered_map<std::string, double> interface_to_last_mark_unhealthy_time;
        for (auto &&i:live_interfaces) {
            auto mark_unhealthy_key = str("interface_mark_unhealthy ", i);
            auto last_disable_interface = global_event_tracker.last_event_for_key(mark_unhealthy_key);
            auto healthy = healthy_interfaces.find(i) != healthy_interfaces.end();
            if (!healthy) {
                global_event_tracker.add_event(
                        {"interface_mark_unhealthy", mark_unhealthy_key},
                        {
                                {"ping_interface",    i},
                                {"if_to_good_target", if_to_good_target[i].size()},
                                {"good_targets",      good_targets.size()},
                        });
                write_unhealthy(i, true);
            } else {
                interface_to_last_mark_unhealthy_time[i] = last_disable_interface
                                                           ? last_disable_interface->event_noticed_unixtime
                                                           : std::nan("");
            }
        }
        std::vector<std::string> healthy_sorted{healthy_interfaces.begin(), healthy_interfaces.end()};
        std::sort(healthy_sorted.begin(), healthy_sorted.end(), [&](auto &&a, auto &&b) {
            return interface_to_last_mark_unhealthy_time[a] < interface_to_last_mark_unhealthy_time[b];
        });
        bool first_healthy = true;
        for (auto &&i:healthy_sorted) {
            if (!first_healthy &&
                !(interface_to_last_mark_unhealthy_time[i] >=
                  now - env("wait_before_mark_interface_healthy_seconds", 3600.0))) {
                break;
            }
            first_healthy = false;
            global_event_tracker.add_event(
                    {"interface_mark_healthy", str("interface_mark_healthy ", i)},
                    {
                            {"ping_interface",           i},
                            {"if_to_good_target",        if_to_good_target[i].size()},
                            {"good_targets",             good_targets.size()},
                            {"last_mark_unhealthy_time", interface_to_last_mark_unhealthy_time[i]},
                    });

            write_unhealthy(i, false);
        }
        if (interfaces_have_changed) {
            std::system(env("health_change_watcher_command", "shorewall reload").c_str());
        }
    }
};

template<typename Container>
void ping_all_addresses(Container const &known_ifs, ping_record_store &ping_store, double now = now_unixtime()) {
    ping_health_decider health_decider;
    auto last_ping_all_addresses = global_event_tracker.last_event_for_key("ping_all_addresses");
    auto last_icmp_sent = global_event_tracker.last_event_for_key("icmp_echo");
    auto current_ping_all_addresses = global_event_tracker.add_event(
            {"ping_all_addresses"},
            {
                    {"target_ping_ips", health_decider.target_ping_ips.size()},
                    {"known_ifs",       known_ifs.size()},
            });

    ping_sender sender{ping_store};
    for (auto const&[if_name, addrs]:known_ifs) {
        if (!std::regex_match(if_name, std::regex(env("ping_interface_name_regex", ".*")))) {
            continue;
        }
        health_decider.live_interfaces.insert(if_name);
        health_decider.if_to_good_target[if_name]; // force creation
        for (sockaddr const &src_addr: addrs) {
            union {
                sockaddr_in dest_addr;
                sockaddr dest_sockaddr;
            } da;
            std::memset(&da, 0, sizeof(da));
            da.dest_addr.sin_family = AF_INET;

            for (auto &&dest:health_decider.target_ping_ips) {
                auto reply = global_event_tracker.last_event_for_key(str("icmp_echoreply to ", dest, " if ", if_name));

                if (last_ping_all_addresses && reply &&
                    reply->event_noticed_unixtime >= last_ping_all_addresses->event_noticed_unixtime) {
                    health_decider.if_to_good_target[if_name][dest] = reply.value();
                    ++health_decider.good_targets[dest];
                }

                CALL_ERRNO_BAD_VALUE(inet_pton, 0, AF_INET, dest.c_str(), &da.dest_addr.sin_addr);
                try {
                    for (auto i = env("ping_repeat_count", 3); i != 0; --i) {
                        sender.send_ping(src_addr, da.dest_sockaddr, if_name);
                    }
                } catch (std::exception const &e) {
                    std::cerr << "cannot ping on " << if_name << ": " << e.what() << std::endl;
                }
            }
        }
    }
    if (last_ping_all_addresses && last_icmp_sent) {
        auto healthy = health_decider.decide_health();
        health_decider.act_on_healthy_interfaces(std::move(healthy));
    }
}

int global_exit_value;

void signal_callback_handler(int signum) {
    global_exit_value = signum;
}

int main() {
    signal(SIGINT, signal_callback_handler);
    signal(SIGTERM, signal_callback_handler);

    network_interfaces_manager interfaces_manager;
    global_event_tracker.add_event({"rebootping_init"},
                                   {{"compilation_timestamp", __TIMESTAMP__}});
    auto last_dump_info_time = now_unixtime();
    while (!global_exit_value) {
        auto known_ifs = interfaces_manager.discover_known_ifs();
        std::this_thread::sleep_for(std::chrono::duration<double>(env("ping_heartbeat_spacing_seconds", 1.0)));
        ping_all_addresses(known_ifs, interfaces_manager.ping_store);

        auto now = now_unixtime();
        if (now > last_dump_info_time + env("dump_info_spacing_seconds", 60.0)) {
            last_dump_info_time = now;
            interfaces_manager.report_html();
        }
    }
    global_event_tracker.add_event({"rebootping_exit"},
                                   {{"global_exit_value", (double) global_exit_value}});
    return global_exit_value;
}
