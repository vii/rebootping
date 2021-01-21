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
                case '\b':
                    os << "\\b";
                    break;
                case '\f':
                    os << "\\f";
                    break;
                case '\n':
                    os << "\\n";
                    break;
                case '\r':
                    os << "\\r";
                    break;
                case '\t':
                    os << "\\t";
                    break;
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
