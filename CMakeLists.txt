cmake_minimum_required(VERSION 3.16)
project(rebootping)
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/")
list(APPEND CXX_FLAGS "-ggdb" "-O2" "-Wall")

find_package(PCAP REQUIRED)
find_package(Threads)

add_library(rebootping_lib limited_pcap_dumper.hpp env.hpp space_estimate_for_path.cpp space_estimate_for_path.hpp file_contents_cache.cpp file_contents_cache.hpp event_tracker.cpp event_tracker.hpp now.hpp str.hpp network_interface_watcher.cpp network_interface_watcher.hpp wire_layout.hpp ping_record_store.cpp ping_record_store.hpp wire_layout.cpp network_interface_watcher.cpp network_interfaces_manager.cpp network_interfaces_manager.hpp make_unique_ptr_closer.hpp call_errno.hpp flat_file_map.cpp flat_file_map.hpp flat_file_string.cpp flat_file_string.hpp flat_file_string_pool.cpp flat_file_string_pool.hpp flat_file_records.cpp flat_file_records.hpp)

add_executable(rebootping rebootping_main.cpp)

target_include_directories(rebootping_lib PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(rebootping_lib ${PCAP_LIBRARY} Threads::Threads)
target_link_libraries(rebootping rebootping_lib)
