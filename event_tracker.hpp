#pragma once

#include "env.hpp"
#include "now.hpp"

#include <unordered_map>
#include <string>
#include <variant>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <list>
#include <memory>
#include <iostream>
#include <iomanip>

using event_tracker_value = std::variant<
        std::string,
        double,
        uint64_t
>;

struct event_tracker_contents : std::unordered_map<std::string, event_tracker_value> {
    double event_noticed_unixtime = now_unixtime(); // not necessarily the time the underlying activity happened

    inline event_tracker_value const &operator[](std::string const &key) const {
        auto i = find(key);
        if (i == end()) {
            throw std::runtime_error("unknown_event_tracker_contents_key " + key);
        }
        return i->second;
    }
};

inline std::ostream &operator<<(std::ostream &os, event_tracker_value const &val) {
    std::visit([&](auto &&v) {
        os << v;
    }, val);
    return os;
}

struct event_tracker_event : event_tracker_contents {
    std::vector<std::string> event_keys;
    std::vector<std::pair<std::list<event_tracker_event *> *, std::list<event_tracker_event *>::iterator>> event_iterators;

    event_tracker_event(std::initializer_list<std::string> keys,
                        std::initializer_list<event_tracker_contents::value_type> contents
    );

    event_tracker_event(event_tracker_event const &) = delete;

    event_tracker_event &operator=(event_tracker_event const &) = delete;

    ~event_tracker_event();
};

std::ostream &operator<<(std::ostream &os, event_tracker_event const &e);

class event_tracker {
    std::list<std::unique_ptr<event_tracker_event> > event_by_age;
    std::mutex event_mutex;

    std::unordered_map<std::string, std::list<event_tracker_event *> > event_by_key;
public:
    event_tracker();

    event_tracker(event_tracker const &) = delete;

    event_tracker &operator=(event_tracker const &) = delete;

    event_tracker_contents add_event(std::unique_ptr<event_tracker_event> &&event_ptr);

    inline event_tracker_contents add_event(std::initializer_list<std::string> keys,
                                            std::initializer_list<event_tracker_contents::value_type> contents
    ) {
        return add_event(std::make_unique<event_tracker_event>(keys, contents));
    }

    template<typename Walker>
    inline void walk_key(std::string const &key, Walker w) {
        std::lock_guard _{event_mutex};

        for (auto &&e:event_by_key[key]) {
            if (!w(*e)) {
                return;
            }
        }
    }

    std::optional<event_tracker_contents> last_event_for_key(std::string const &key);

    ~event_tracker();
};

extern event_tracker event_tracker;
