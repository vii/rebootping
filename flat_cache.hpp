#pragma once

#include "flat_hash.hpp"
#include "flat_record.hpp"

template<typename record_type, typename should_expire_function, typename hash_function = flat_hash_function_class>
struct flat_cache {};