#pragma once

#include "env.hpp"

#define define_flat_env(name, default_value)                                                                                                                   \
    namespace flat_env {                                                                                                                                       \
    inline auto name() -> decltype(env(#name, default_value)) { return env(#name, default_value); }                                                            \
    }

define_flat_env(oui_database_filename, "/var/lib/ieee-data/oui.txt");
define_flat_env(obfuscate_address, false);
define_flat_env(obfuscate_address_reveal_prefix, 8);
define_flat_env(timeshard_strftime_format, "%Y%m%d");
