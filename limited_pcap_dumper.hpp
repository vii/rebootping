#pragma once

#include "env.hpp"
#include "space_estimate_for_path.hpp"
#include "str.hpp"
#include "wire_layout.hpp"

#include <pcap/pcap.h>

#include <atomic>
#include <filesystem>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>

struct limited_pcap_dumper {
    std::string pcap_filename;
    std::filesystem::path pcap_dir;
    pcap_dumper_t *pcap_dumper = nullptr;
    std::uintmax_t pcap_filesize = 0;

    bool can_write_bytes(uintmax_t len) {
        auto ret = std::cmp_less(pcap_filesize + len, env("limited_pcap_dumper_max_dump_bytes", 100 * 1024 * 1024)) &&
                   std::cmp_greater_equal(space_estimate_for_path(pcap_dir, len), env("limited_pcap_dumper_min_available_bytes", 1 * 1024 * 1024 * 1024));
        if (ret) { pcap_filesize += len; }
        return ret;
    }

    limited_pcap_dumper(pcap_t *pcap_session, std::string const &filename)
        : pcap_filename(filename), pcap_dir(std::filesystem::absolute(std::filesystem::path(filename)).parent_path()) {
        std::error_code file_size_check_error;
        auto size = std::filesystem::file_size(pcap_filename, file_size_check_error);
        if (!file_size_check_error) { pcap_filesize = size; }
        if (can_write_bytes(sizeof(pcap_file_header))) {
            pcap_dumper = pcap_dump_open_append(pcap_session, pcap_filename.c_str());
            if (!pcap_dumper) { std::cerr << "pcap_dump_open_append " << pcap_filename << ": " << pcap_geterr(pcap_session) << std::endl; }
        }
    }

    void pcap_dump_packet(const struct pcap_pkthdr *h, const u_char *bytes) {
        if (!pcap_dumper) { return; }
        if (!can_write_bytes(sizeof(pcap_pkthdr) + h->caplen)) {
            close_dumper();
            return;
        }
        pcap_dump((u_char *)pcap_dumper, h, bytes);
        auto flush_ret = pcap_dump_flush(pcap_dumper);
        if (flush_ret != 0) { std::cerr << "pcap_dump_flush " << pcap_filename << ": failed" << std::endl; }
    }

    ~limited_pcap_dumper() { close_dumper(); }

    void close_dumper() {
        if (pcap_dumper) {
            pcap_dump_close(pcap_dumper);
            pcap_dumper = nullptr;
        }
    }

    limited_pcap_dumper(limited_pcap_dumper const &) = delete;

    limited_pcap_dumper &operator=(limited_pcap_dumper const &) = delete;
};

inline std::string limited_pcap_dumper_filename(std::string_view interface_name, const macaddr &ma) { return str("dump_", interface_name, "_", ma, ".pcap"); }