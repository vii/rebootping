#include <cmath>
#include "event_tracker.hpp"

struct event_tracker event_tracker;

event_tracker_contents event_tracker::add_event(std::unique_ptr<event_tracker_event> &&event_ptr) {
    event_tracker_event &event = *event_ptr;
    std::lock_guard _{event_mutex};
    std::cout << event << std::endl;
    event_by_age.push_back(std::move(event_ptr));
    for (auto &&k:event.event_keys) {
        auto &event_list = event_by_key[k];
        event.event_iterators.emplace_back(
                &event_list, event_list.insert(event_list.begin(), &event)
        );
    }
    while (event_by_age.size() > env("event_tracker_max_size", 1024 * 1024)) {
        event_by_age.pop_front();
    }
    return event;
}

std::optional<event_tracker_contents> event_tracker::last_event_for_key(const std::string &key) {
    std::optional<event_tracker_contents> ret;

    walk_key(key, [&](auto const &e) {
        ret = e;
        return false;
    });
    return ret;
}

event_tracker::~event_tracker() {
    std::lock_guard _{event_mutex};
    event_by_age.clear();
}

event_tracker::event_tracker() {}

event_tracker_event::~event_tracker_event() {
    for (auto&&[list, i]:event_iterators) {
        list->erase(i);
    }
    event_iterators.clear();
}

event_tracker_event::event_tracker_event(std::initializer_list<std::string> keys,
                                         std::initializer_list<event_tracker_contents::value_type> contents)
        : event_keys(keys) {
    insert(contents.begin(), contents.end());
}

namespace {
    void escape_json_string(std::ostream &os, std::string const &s) {
        os << '"';
        for (auto &&c:s) {
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
        os << '\"';
    }
}


std::ostream &operator<<(std::ostream &os, const event_tracker_event &e) {
    os << std::setprecision(20) << e.event_noticed_unixtime << " {";
    os << "\"event_keys\":[";
    bool first_key = true;
    for (auto &&k:e.event_keys) {
        if (!first_key) {
            os << ',';
        }
        escape_json_string(os, k);
        first_key = false;
    }
    os << ']';
    for (auto&&[k, v]:e) {
        os << ',';
        escape_json_string(os, k);
        os << ": ";
        std::visit([&](auto &&val) {
            using T = std::decay_t<decltype(val)>;
            if constexpr (std::is_same_v<T, std::string>) {
                escape_json_string(os, val);
            } else if (std::is_same_v<T, uint64_t>) {
                if (val < (1 << 31)) {
                    os << val;
                } else {
                    os << '"' << val << '"';
                }
            } else if (std::is_same_v<T, double> && std::isnan(val)) {
                os << "null";
            } else {
                os << val;
            }
        }, v);
    }
    return os << "}";
}
