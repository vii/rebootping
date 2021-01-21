#include "wire_layout.hpp"
#include "call_errno.hpp"
#include "flat_env.hpp"
#include "str.hpp"
#include <fstream>
#include <regex>

std::ostream &operator<<(std::ostream &os, const in_addr &i) {
    char str[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &i, str, sizeof(str))) {
        return os << "inet_ntop_failed";
    }
    return os << str;
}

std::ostream &operator<<(std::ostream &os, const sockaddr &s) {
    char str[INET6_ADDRSTRLEN + INET_ADDRSTRLEN];
    if (auto ret = getnameinfo(&s, sizeof(s), str, sizeof(str),
                               nullptr, 0, NI_NUMERICHOST | NI_NUMERICSERV)) {
        return os << "getnameinfo failed " << gai_strerror(ret);
    } else {
        return os << str;
    }
}

double origin_ip_address_score(ip_header const &ip) {
    switch (ip.ip_ttl) {
        // MS Windows starts ttl at 128, Linux and MacOS X at 64;
        // of course it is possible that an Internet host would set a higher ttl and then
        // have it match 64 or 128 when it passes through
        case 64:
        case 128:
            return 1.0;
        default:
            // the higher the better; could use popcount to find lowest number of bits
            // set - as people seem to like simple powers of two for defaults
            return ip.ip_ttl / 256.0;
    }
}

namespace {
    std::unordered_map<uint32_t, std::string> load_oui_db() {
        std::unordered_map<uint32_t, std::string> ret;

        auto stream = std::ifstream{flat_env::oui_database_filename()};
        auto manufacturer_regex = std::regex("([[:xdigit:]]{6})[[:space:]]+\\([^)]*\\)[[:space:]]+(.+)",
                                             std::regex::extended);

        for (std::string line; std::getline(stream, line);) {
            std::smatch matches;
            if (!std::regex_match(line, matches, manufacturer_regex)) {
                continue;
            }
            ret[std::strtol(matches[1].str().c_str(), nullptr, 16)] = matches[2];
        }

        return ret;
    }
}// namespace

std::string oui_manufacturer_name(macaddr const &macaddr) {
    static auto oui_db = load_oui_db();
    auto i = oui_db.find(macaddr.mac_manufacturer());
    if (i == oui_db.end()) {
        return {};
    }
    return i->second;
}

std::string services_port_name(int port, const std::string &proto) {
    servent servbuf;
    servent *result = nullptr;
    char buffer[BUFSIZ];
    auto ret = getservbyport_r(
            htons(port),
            proto.c_str(),
            &servbuf,
            buffer,
            sizeof(buffer),
            &result);
    if (ret || !result) {
        return {};
    }
    return result->s_name;
}

sockaddr sockaddr_from_string(const std::string &src, sa_family_t sin_family) {
    union {
        sockaddr_in dest_addr;
        sockaddr dest_sockaddr;
    } da;
    std::memset(&da, 0, sizeof(da));
    da.dest_addr.sin_family = sin_family;
    CALL_ERRNO_BAD_VALUE(inet_pton, 0, da.dest_addr.sin_family, src.c_str(), &da.dest_addr.sin_addr);
    return da.dest_sockaddr;
}

std::string maybe_obfuscate_address_string(std::string_view address) {
    auto reveal_prefix = flat_env::obfuscate_address_reveal_prefix();
    if (flat_env::obfuscate_address() && address.size() > reveal_prefix) {
        return str(address.substr(0, reveal_prefix), "...");
    } else {
        return std::string{address};
    }
}