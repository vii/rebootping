#pragma once

#include "env.hpp"
#include <fstream>

void report_html_dump(std::ostream&out);

inline void report_html_dump() {
    std::ofstream out{env("output_html_dump_filename", "index.html")};
    report_html_dump(out);
}

