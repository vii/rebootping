#include "escape_json.hpp"

#include <cmath>
#include <iomanip>
#include <iostream>

std::ostream &operator<<(std::ostream &os, escape_json_tag<std::string_view> s) {
    os << '"';
    for (auto &&c : s.escape_value) {
        // https://www.json.org/json-en.html
        if (std::iscntrl(c) || c < 32) {
            switch (c) {
            case '\b': os << "\\b"; break;
            case '\f': os << "\\f"; break;
            case '\n': os << "\\n"; break;
            case '\r': os << "\\r"; break;
            case '\t': os << "\\t"; break;
            default:
                os << "\\u";
                os << std::setfill('0') << std::setw(4) << std::right << std::hex << static_cast<uint8_t>(c);
                break;
            }
        } else if (c == '\"' || c == '\\') {
            os << '\\' << c;
        } else {
            os << c;
        }
    }
    return os << '\"';
}

std::ostream &operator<<(std::ostream &os, escape_json_tag<double> s) {
    if (std::isnan(s.escape_value)) {
        return os << "null";
    } else {
        return os << std::setprecision(std::numeric_limits<double>::digits10 + 1) << s.escape_value;
    }
}

std::string escape_html_string(std::string const &s) {
    std::string ret;
    ret.reserve(s.size());
    for (auto c : s) {
        switch (c) {
        case '"': ret += "&quot;"; break;
        case '\'': ret += "&apos;"; break;
        case '&': ret += "&amp;"; break;
        case '<': ret += "&lt;"; break;
        case '>': ret += "&gt;"; break;
        default: ret += c; break;
        }
    }
    return ret;
}
