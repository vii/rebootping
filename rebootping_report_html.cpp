#include "rebootping_report_html.hpp"
#include "ping_health_decider.hpp"
#include "ping_record_store.hpp"

namespace {
    template<typename input_type>
    std::string escape_html(input_type &&in) {
        auto s = str(in);//TODO actually escape it
        return s;
    }

    std::string_view interface_health_record_status_string(flat_timeshard_iterator_interface_health_record const &record) {
        if (std::isnan(record.health_decision_unixtime())) {
            return "Unknown";
        }
        if (record.health_last_good_unixtime() == record.health_decision_unixtime()) {
            return "Good";
        }
        if (record.health_last_bad_unixtime() == record.health_decision_unixtime()) {
            return "Bad";
        }
        return "Impossible";
    }
}// namespace

void report_html_dump(std::ostream &out) {
    out << R"(
<html>
<head>
    <title>rebootping</title>
    <link rel=stylesheet href="rebootping_style.css">
    <script type="text/javascript" src="rebootping_script.js"></script>
</head>
<body>
)";

    out << "<h1>Interface statuses</h1>\n";
    auto interfaces = interface_health_record_store().health_interface_index();

    out << R"(
<table>
    <thead>
        <tr>
            <th>Interface</th>
            <th>Interface status</th>
            <th>Interface last good</th>
            <th>Interface last bad</th>
            <th>Interface last decision</th>
        </tr>
    </thead>
    <tbody>
)";
    for (auto &&[interface, record] : interfaces) {
        out << R"(
        <tr>
            <th>)"
            << escape_html(interface) << R"(</th>
            <td class=interface_health_record_status>)"
            << escape_html(interface_health_record_status_string(record)) << R"(</td>
            <td class=unixtime>)"
            << record.health_last_good_unixtime() << R"(</td>
            <td class=unixtime>)"
            << record.health_last_bad_unixtime() << R"(</td>
            <td class=unixtime>)"
            << record.health_decision_unixtime() << R"(</td>
        </tr>
)";
    }
    out << R"(
    </tbody>
</table>
)";


    //    interface_health_record_store().health_interface()

    /*

    output_html_table_for_event_key(out, "interface_mark_unhealthy",
                                    env("report_html_max_unhealthy", 1000));

    out << "<h1>Lost pings</h1>\n";
    output_html_table_for_event_key(
            out,
            "lost_ping",
            env("report_html_max_lost_pings", 1000));

    out << "<h1>Pings</h1>\n";
    output_html_table_for_event_key(
            out,
            "icmp_echoreply",
            env("report_html_max_pings", 20000));
*/
    out << "<script>rebootping_process_html()</script>\n</body>\n";
};