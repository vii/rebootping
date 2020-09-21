#include "wire_layout.hpp"

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
