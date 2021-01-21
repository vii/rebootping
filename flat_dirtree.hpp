#pragma once

#include "flat_mmap.hpp"

#include <filesystem>
#include <numeric>
#include <ranges>
#include <unordered_map>
#include <vector>

double string_to_unixtime(std::string_view s);

std::vector<std::string> fetch_flat_timeshard_dirs(std::string_view flat_dir);


template<typename timeshard_type, typename timeshard_iterator_type>
struct flat_dirtree {
    std::string flat_dir;
    flat_mmap_settings flat_settings;
    std::vector<timeshard_type> flat_timeshards;
    std::unordered_map<std::string, timeshard_type *> flat_name_to_timeshard;

    flat_dirtree(std::string_view dir, flat_mmap_settings const &settings = flat_mmap_settings()) : flat_dir{dir}, flat_settings{settings} {
        reset_flat_timeshards();
    }

    void reset_flat_timeshards() {
        auto new_dirs = fetch_flat_timeshard_dirs(flat_dir);
        // ranges are not easily convertible to vector in C++20
        // https://timur.audio/how-to-make-a-container-from-a-c20-range

        flat_name_to_timeshard.clear();
        flat_timeshards.clear();
        flat_timeshards.reserve(new_dirs.size());

        for (auto const &d : new_dirs) {
            insert_new_timeshard(d);
        }
    }

    typename std::vector<timeshard_type>::iterator timeshard_iter_including(double unixtime) {
        auto after = std::lower_bound(flat_timeshards.begin(), flat_timeshards.end(),
                                      unixtime,
                                      [](timeshard_type const &s, double unixtime) {
                                          return string_to_unixtime(s.flat_timeshard_name) < unixtime;
                                      });
        if (after == flat_timeshards.begin()) {
            return after;
        }
        --after;
        return after;
    }

    typename std::vector<timeshard_type>::iterator timeshard_iter_after(double unixtime) {
        return std::upper_bound(flat_timeshards.begin(), flat_timeshards.end(),
                                unixtime,
                                [](double unixtime, timeshard_type const &s) {
                                    return string_to_unixtime(s.flat_timeshard_name) > unixtime;
                                });
    }

    typename decltype(flat_name_to_timeshard)::iterator insert_new_timeshard(std::string const &timeshard_name) {
        return flat_name_to_timeshard.insert_or_assign(timeshard_name,
                                                       &flat_timeshards.emplace_back(timeshard_name,
                                                                                     flat_dir + "/" + timeshard_name,
                                                                                     flat_settings))
                .first;
    }

    template<typename add_function>
    void add_flat_record(std::string const &timeshard_name, add_function f) {
        auto i = flat_name_to_timeshard.find(timeshard_name);
        if (i == flat_name_to_timeshard.end()) {
            if (flat_settings.mmap_readonly) {
                throw std::runtime_error("add_flat_record to new shard while readonly: " + std::string(timeshard_name));
            }
            std::filesystem::create_directories(flat_dir + "/" + std::string(timeshard_name));
            i = insert_new_timeshard(timeshard_name);
            i->second->timeshard_reset_header();
        }
        auto &timeshard = *i->second;
        auto index = timeshard.timeshard_header_ref().flat_index_next;
        timeshard.flat_timeshard_ensure_mmapped(index);

        f(timeshard_iterator_type{&timeshard, index});

        timeshard.timeshard_commit_index(index);
    }


    struct flat_dirtree_iterator : std::iterator<std::input_iterator_tag, timeshard_iterator_type> {
        typename std::vector<timeshard_type>::iterator outer_iterator;
        uint64_t flat_iterator_index = 0;

        flat_dirtree_iterator() = default;

        explicit flat_dirtree_iterator(typename std::vector<timeshard_type>::iterator const &it, uint64_t index = 0) : outer_iterator{it}, flat_iterator_index{index} {}

        bool operator==(flat_dirtree_iterator const &other) const {
            return other.outer_iterator == outer_iterator && other.flat_iterator_index == flat_iterator_index;
        }
        bool operator!=(flat_dirtree_iterator const &other) const {
            return !(*this == other);
        }

        flat_dirtree_iterator &operator++() {
            ++flat_iterator_index;

            if (flat_iterator_index >= outer_iterator->timeshard_header_ref().flat_index_next) {
                flat_iterator_index = 0;
                ++outer_iterator;
            }
            return *this;
        }
        const flat_dirtree_iterator operator++(int) {
            auto old = *this;
            ++*this;
            return old;
        }

        timeshard_iterator_type operator*() const {
            return timeshard_iterator_type(&*outer_iterator, flat_iterator_index);
        }

        struct arrow_proxy {
            timeshard_iterator_type proxied;
            timeshard_iterator_type *operator->() {
                return &proxied;
            }
        };

        // for lifetime control https://quuxplusone.github.io/blog/2019/02/06/arrow-proxy/
        arrow_proxy operator->() { return arrow_proxy{*this}; }
    };

    std::ranges::subrange<flat_dirtree_iterator>
    timeshard_query(double start_unixtime = std::numeric_limits<double>::min(),
                    double end_unixtime = std::numeric_limits<double>::max()) {
        auto begin = flat_dirtree_iterator{timeshard_iter_including(start_unixtime)};
        auto end = flat_dirtree_iterator{timeshard_iter_after(end_unixtime)};

        return std::ranges::subrange<flat_dirtree_iterator>(
                begin,
                end);
    }
};