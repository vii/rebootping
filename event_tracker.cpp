#include "event_tracker.hpp"
#include "escape_json.hpp"
#include "str.hpp"

#include <cmath>

event_tracker global_event_tracker;

event_tracker_contents event_tracker::add_event(std::unique_ptr<event_tracker_event> &&event_ptr) {
    event_tracker_event &event = *event_ptr;
    std::lock_guard _{event_mutex};
    std::cout << event << std::endl;
    event_by_age.push_back(std::move(event_ptr));
    for (auto &&k : event.event_keys) {
        auto &event_list = event_by_key[k];
        event.event_iterators.emplace_back(
                &event_list, event_list.insert(event_list.begin(), &event));
    }
    while (std::cmp_greater(event_by_age.size(),env("event_tracker_max_size", 1024 * 1024))) {
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
    for (auto const &[list, i] : event_iterators) {
        list->erase(i);
    }
    event_iterators.clear();
}

event_tracker_event::event_tracker_event(std::initializer_list<std::string> keys,
                                         std::initializer_list<event_tracker_contents::value_type> contents)
    : event_keys(keys) {
    insert(contents.begin(), contents.end());
}


std::ostream &operator<<(std::ostream &os, const event_tracker_event &e) {
    os << std::setprecision(20) << e.event_noticed_unixtime << " {";
    os << "\"event_keys\":[";
    bool first_key = true;
    for (auto &&k : e.event_keys) {
        if (!first_key) {
            os << ',';
        }
        os << escape_json(k);
        first_key = false;
    }
    os << ']';
    for (auto const &[k, v] : e) {
        os << ',' << escape_json(k) << ": ";
        std::visit([&](auto &&val) {
            os << escape_json(val);
        },
                   v);
    }
    return os << "}";
}
