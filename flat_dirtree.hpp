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

template<typename timeshard_schema_type>
struct flat_dirtree {
    using timeshard_type = typename timeshard_schema_type::flat_schema_timeshard;
    using timeshard_iterator_type = typename timeshard_schema_type::flat_schema_timeshard_iterator;
    std::string flat_dir;
    std::string flat_dir_suffix;
    flat_mmap_settings flat_settings;
    std::vector<std::unique_ptr<timeshard_type>> flat_timeshards;
    std::unordered_map<std::string, timeshard_type *> flat_name_to_timeshard;

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

    typename decltype(flat_timeshards)::reverse_iterator timeshard_reverse_iter_including(double unixtime) {
        auto after = std::lower_bound(flat_timeshards.rbegin(), flat_timeshards.rend(),
                                      unixtime,
                                      [](std::unique_ptr<timeshard_type> const &s, double unixtime) {
                                          return string_to_unixtime(s->flat_timeshard_name) > unixtime;
                                      });
        if (after == flat_timeshards.rbegin()) {
            return after;
        }
        --after;
        return after;
    }

    typename decltype(flat_timeshards)::reverse_iterator timeshard_reverse_iter_before(double unixtime) {
        return std::upper_bound(flat_timeshards.rbegin(), flat_timeshards.rend(),
                                unixtime,
                                [](double unixtime, std::unique_ptr<timeshard_type> const &s) {
                                    return string_to_unixtime(s->flat_timeshard_name) < unixtime;
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

    timeshard_type *timeshard_name_to_timeshard(std::string_view timeshard_name, bool create_missing = true) {
        auto i = flat_name_to_timeshard.find(std::string(timeshard_name));
        if (i == flat_name_to_timeshard.end()) {
            if (flat_settings.mmap_readonly || !create_missing) {
                return nullptr;
            }
            std::filesystem::create_directories(flat_dir + "/" + std::string(timeshard_name) + "/" + flat_dir_suffix);
            i = insert_new_timeshard(timeshard_name);
        }
        return &*i->second;
    }

    timeshard_type *unixtime_to_timeshard(double unixtime, bool create_missing = true) {
        return timeshard_name_to_timeshard(yyyymmdd(unixtime), create_missing);
    }

    template<typename add_function>
    timeshard_iterator_type add_flat_record(std::string_view timeshard_name, add_function &&f) {
        auto shard = timeshard_name_to_timeshard(timeshard_name);

        if (!shard) {
            if (flat_settings.mmap_readonly) {
                throw std::runtime_error("timeshard_name_to_timeshard to new shard while readonly: " + std::string(timeshard_name));
            } else {
                throw std::runtime_error("timeshard_name_to_timeshard cannot create timeshard: " + std::string(timeshard_name));
            }
        }

        return add_flat_record(*shard, std::forward<add_function>(f));
    }

    template<typename add_function>
    timeshard_iterator_type add_flat_record(timeshard_type &timeshard, add_function &&f) {
        auto index = timeshard.timeshard_header_ref().flat_timeshard_index_next;
        timeshard.flat_timeshard_ensure_mmapped(index);

        auto iter = timeshard_iterator_type{&timeshard, index};
        f(iter);
        flat_indices_commit(timeshard, iter);

        timeshard.timeshard_commit_index(index);

        return iter;
    }

    template<typename add_function>
    timeshard_iterator_type add_flat_record(double unixtime, add_function &&f) {
        return add_flat_record(*unixtime_to_timeshard(unixtime),
                               std::forward<add_function>(f));
    }

    template<typename add_function>
    timeshard_iterator_type add_flat_record(add_function &&f) {
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
        arrow_proxy operator->() { return arrow_proxy{**this}; }

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

    template<typename key_type, typename obj_to_field_mapper>
    struct flat_dirtree_search_context {
        key_type const search_key;
        obj_to_field_mapper const search_obj_to_field_mapper;
    };
    template<typename search_context>
    struct flat_dirtree_linked_index_iterator : std::iterator<std::input_iterator_tag, timeshard_iterator_type> {
        std::shared_ptr<search_context > iter_search_context;
        typename decltype(flat_timeshards)::const_reverse_iterator iter_timeshard;
        typename decltype(flat_timeshards)::const_reverse_iterator iter_stop_timeshard;
        timeshard_iterator_type iter_record;

        flat_dirtree_linked_index_iterator() = default;

        flat_dirtree_linked_index_iterator(
                std::shared_ptr<search_context> context,
                decltype(iter_timeshard) const &start,
                decltype(iter_stop_timeshard) const &end) : iter_search_context(context),
                                                            iter_timeshard(start), iter_stop_timeshard(end) {
            step_timeshard();
        }

        bool operator==(flat_dirtree_linked_index_iterator const &i) const {
            if (!!iter_search_context != !!i.iter_search_context) {
                return false;
            }
            if (!!iter_search_context && (iter_search_context->search_key != i.iter_search_context->search_key)) {
                return false;
            }
            return iter_timeshard == i.iter_timeshard &&
                   iter_record == i.iter_record;
        }
        bool operator!=(flat_dirtree_linked_index_iterator const &i) const {
            return !(*this == i);
        }

        void step_timeshard() {
            while (iter_timeshard != iter_stop_timeshard) {
                if (iter_record) {
                    auto next_index = iter_search_context->search_obj_to_field_mapper(iter_record);
                    if (next_index) {
                        iter_record.flat_iterator_index = next_index - 1;
                        break;
                    }
                } else if (auto lookup = iter_search_context->search_obj_to_field_mapper(**iter_timeshard).flat_timeshard_index_lookup_key(iter_search_context->search_key)) {
                    iter_record = timeshard_iterator_type(&**iter_timeshard, *lookup - 1);
                    break;
                }
                ++iter_timeshard;
                iter_record = timeshard_iterator_type();
            }
        }

        flat_dirtree_linked_index_iterator &operator++() {
            step_timeshard();
            return *this;
        }
        flat_dirtree_linked_index_iterator operator++(int) {
            auto old = *this;
            ++*this;
            return old;
        }

        timeshard_iterator_type &operator*() {
            assert(iter_record);
            return iter_record;
        }
        timeshard_iterator_type *operator->() {
            assert(iter_record);
            return &iter_record;
        }
    };

    template<typename search_context>
    struct flat_dirtree_linked_index_subrange : std::ranges::subrange<flat_dirtree_linked_index_iterator<search_context> > {
        flat_dirtree &iter_dirtree;
        std::shared_ptr<search_context> iter_search_context;
        using std::ranges::subrange<flat_dirtree_linked_index_iterator<search_context>>::end;

        flat_dirtree_linked_index_subrange(
                flat_dirtree &tree,
                std::shared_ptr<search_context> context,
                const flat_dirtree_linked_index_iterator<search_context>& start,
                const flat_dirtree_linked_index_iterator<search_context>& end)
            : std::ranges::subrange<flat_dirtree_linked_index_iterator<search_context>>(
                      start, end),
              iter_dirtree(tree),
              iter_search_context(context) {}

        timeshard_iterator_type add_if_missing(double unixtime = now_unixtime()) {
            return add_if_missing([](timeshard_iterator_type const &iter) {}, unixtime);
        }


        template<typename add_function>
        timeshard_iterator_type add_if_missing(add_function &&f, double unixtime = now_unixtime()) {
            timeshard_type *last_timeshard = iter_dirtree.unixtime_to_timeshard(unixtime);
            auto &timeshard_field = iter_search_context->search_obj_to_field_mapper(*last_timeshard);
            if (auto lookup = timeshard_field.flat_timeshard_index_lookup_key(iter_search_context->search_key)) {
                return timeshard_iterator_type(last_timeshard, *lookup - 1);
            }
            return iter_dirtree.add_flat_record(*last_timeshard, [&](timeshard_iterator_type &iter) {
                f(iter);
                timeshard_field.flat_timeshard_index_set_key(iter_search_context->search_key, iter);
            });
        }

        void set_index(timeshard_iterator_type const &iter) {
            auto &timeshard_field = iter_search_context->search_obj_to_field_mapper(*iter.flat_iterator_timeshard);
            timeshard_field.flat_timeshard_index_set_key(iter_search_context->search_key, iter);
        }
    };

    template<typename key_type, typename obj_to_field_mapper>
    decltype(auto) dirtree_field_query(key_type&&iter_key, double start_unixtime, double end_unixtime, obj_to_field_mapper &&mapper) {
        // TODO fix object lifetimes
        auto begin = timeshard_reverse_iter_including(end_unixtime);
        auto end = timeshard_reverse_iter_before(start_unixtime);
        using search_context = flat_dirtree_search_context<std::decay_t<key_type>,obj_to_field_mapper>;
        auto context = std::make_shared<search_context>(iter_key,mapper);
        flat_dirtree_linked_index_iterator<search_context> end_iter(context, end, end);
        flat_dirtree_linked_index_iterator<search_context> start_iter(context, begin, end);
        return flat_dirtree_linked_index_subrange<search_context>(
                *this,
                context,
                start_iter,
                end_iter);
    }
    template<typename obj_to_field_mapper, typename... arg_types>
    void dirtree_field_walk(double start_unixtime, double end_unixtime, obj_to_field_mapper &&mapper, arg_types&& ...args) {
        auto begin = timeshard_reverse_iter_including(end_unixtime);
        auto end = timeshard_reverse_iter_before(start_unixtime);
        for (auto i =begin; i!=end;++i) {
            mapper(**i).template flat_timeshard_field_walk<timeshard_schema_type>(args...);
        }
    }
    template<typename obj_to_field_mapper>
    decltype(auto) dirtree_field_walk(double start_unixtime, double end_unixtime, obj_to_field_mapper &&mapper) {
        auto begin = timeshard_reverse_iter_including(end_unixtime);
        auto end = timeshard_reverse_iter_before(start_unixtime);
        std::unordered_map<typename std::decay_t<decltype(mapper(**begin))>::field_hydrated_key_type, timeshard_iterator_type > ret;
        for (auto i =begin; i!=end;++i) {
            mapper(**i).template flat_timeshard_field_walk<timeshard_schema_type>([&](auto&&k, auto&&v){
                ret[k] = v;
            });
        }
        return ret;
    }

};
