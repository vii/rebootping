#pragma once

#include "flat_mmap.hpp"
#include "now_unixtime.hpp"

#include <filesystem>
#include <iostream>
#include <numeric>
#include <ranges>
#include <unordered_map>
#include <vector>

double string_to_unixtime(std::string_view s);

std::vector<std::string> fetch_flat_timeshard_dirs(std::string_view flat_dir, std::string_view flat_dir_suffix);

template<typename timeshard_type, typename timeshard_iterator_type>
void flat_indices_commit(timeshard_type &timeshard, timeshard_iterator_type &iter) {}

template<typename timeshard_type, typename timeshard_iterator_type>
struct flat_dirtree {
    std::string flat_dir;
    std::string flat_dir_suffix;
    flat_mmap_settings flat_settings;
    std::vector<std::unique_ptr<timeshard_type>> flat_timeshards;
    std::unordered_map<std::string, timeshard_type *> flat_name_to_timeshard;
    using timeshard_iterator = timeshard_iterator_type;

    flat_dirtree(std::string_view dir, std::string_view after_shard_suffix, flat_mmap_settings const &settings = flat_mmap_settings())
        : flat_dir{dir}, flat_dir_suffix{after_shard_suffix}, flat_settings{settings} {
        assert(!dir.empty());
        assert(!after_shard_suffix.empty());
        reset_flat_timeshards();
    }

    void reset_flat_timeshards() {
        auto new_dirs = fetch_flat_timeshard_dirs(flat_dir, flat_dir_suffix);
        // ranges are not easily convertible to vector in C++20
        // https://timur.audio/how-to-make-a-container-from-a-c20-range

        flat_name_to_timeshard.clear();
        flat_timeshards.clear();
        flat_timeshards.reserve(new_dirs.size());

        for (auto const &d : new_dirs) {
            insert_new_timeshard(d);
        }
    }

    typename decltype(flat_timeshards)::iterator timeshard_iter_including(double unixtime) {
        auto after = std::lower_bound(flat_timeshards.begin(), flat_timeshards.end(),
                                      unixtime,
                                      [](std::unique_ptr<timeshard_type> const &s, double unixtime) {
                                          return string_to_unixtime(s->flat_timeshard_name) < unixtime;
                                      });
        if (after == flat_timeshards.begin()) {
            return after;
        }
        --after;
        return after;
    }

    typename decltype(flat_timeshards)::iterator timeshard_iter_after(double unixtime) {
        return std::upper_bound(flat_timeshards.begin(), flat_timeshards.end(),
                                unixtime,
                                [](double unixtime, std::unique_ptr<timeshard_type> const &s) {
                                    return string_to_unixtime(s->flat_timeshard_name) > unixtime;
                                });
    }

    typename decltype(flat_name_to_timeshard)::iterator insert_new_timeshard(std::string_view timeshard_name) {
        return flat_name_to_timeshard.insert_or_assign(std::string(timeshard_name),
                                                       flat_timeshards.emplace_back(
                                                                              std::make_unique<timeshard_type>(timeshard_name,
                                                                                                               flat_dir + "/" + std::string(timeshard_name) + "/" + flat_dir_suffix,
                                                                                                               flat_settings))
                                                               .get())
                .first;
    }

    timeshard_type *timeshard_name_to_timeshard(std::string_view timeshard_name, bool readonly = false) {
        auto i = flat_name_to_timeshard.find(std::string(timeshard_name));
        if (i == flat_name_to_timeshard.end()) {
            if (flat_settings.mmap_readonly || readonly) {
                return nullptr;
            }
            std::filesystem::create_directories(flat_dir + "/" + std::string(timeshard_name) + "/" + flat_dir_suffix);
            i = insert_new_timeshard(timeshard_name);
        }
        return &*i->second;
    }

    timeshard_type *unixtime_to_timeshard(double unixtime, bool readonly = false) {
        return timeshard_name_to_timeshard(yyyymmdd(unixtime), readonly);
    }

    template<typename add_function>
    void add_flat_record(std::string_view timeshard_name, add_function &&f) {
        auto shard = timeshard_name_to_timeshard(timeshard_name);

        if (!shard) {
            if (flat_settings.mmap_readonly) {
                throw std::runtime_error("timeshard_name_to_timeshard to new shard while readonly: " + std::string(timeshard_name));
            } else {
                throw std::runtime_error("timeshard_name_to_timeshard cannot create timeshard: " + std::string(timeshard_name));
            }
        }

        add_flat_record(*shard, std::forward<add_function>(f));
    }

    template<typename add_function>
    void add_flat_record(timeshard_type &timeshard, add_function &&f) {
        auto index = timeshard.timeshard_header_ref().flat_timeshard_index_next;
        timeshard.flat_timeshard_ensure_mmapped(index);

        auto iter = timeshard_iterator_type{&timeshard, index};
        f(iter);
        flat_indices_commit(timeshard, iter);

        timeshard.timeshard_commit_index(index);
    }

    template<typename add_function>
    void add_flat_record(double unixtime, add_function &&f) {
        return add_flat_record(*unixtime_to_timeshard(unixtime),
                               std::forward<add_function>(f));
    }

    template<typename add_function>
    void add_flat_record(add_function &&f) {
        return add_flat_record(now_unixtime(), std::forward<add_function>(f));
    }


    struct flat_dirtree_iterator : std::iterator<std::input_iterator_tag, timeshard_iterator_type> {
        typename decltype(flat_timeshards)::iterator outer_iterator;
        uint64_t flat_iterator_index = 0;

        flat_dirtree_iterator() = default;

        explicit flat_dirtree_iterator(typename decltype(flat_timeshards)::iterator const &it, uint64_t index = 0) : outer_iterator{it}, flat_iterator_index{index} {}

        bool operator==(flat_dirtree_iterator const &other) const {
            return other.outer_iterator == outer_iterator && other.flat_iterator_index == flat_iterator_index;
        }
        bool operator!=(flat_dirtree_iterator const &other) const {
            return !(*this == other);
        }

        flat_dirtree_iterator &operator++() {
            ++flat_iterator_index;

            if (flat_iterator_index >= (*outer_iterator)->timeshard_header_ref().flat_timeshard_index_next) {
                flat_iterator_index = 0;
                ++outer_iterator;
            }
            return *this;
        }
        flat_dirtree_iterator operator++(int) {
            auto old = *this;
            ++*this;
            return old;
        }

        timeshard_iterator_type operator*() const {
            return timeshard_iterator_type(&**outer_iterator, flat_iterator_index);
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