cmake_minimum_required(VERSION 3.16)
project(rebootping)
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ggdb3 -O -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb3 -fno-omit-frame-pointer -fsanitize=address -fno-eliminate-unused-debug-symbols")

find_package(PCAP REQUIRED)
find_package(Threads)
find_package(Git)

execute_process(COMMAND
        "${GIT_EXECUTABLE}" describe --match=NeVeRmAtCh --always --abbrev=40 --dirty
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE flat_git_sha_string
        OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(COMMAND
        "${GIT_EXECUTABLE}" log -1 --format=%ct
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE flat_git_unixtime
        OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "${GIT_EXECUTABLE} flat_git_unixtime ${flat_git_unixtime} flat_git_sha_string ${flat_git_sha_string}")

configure_file("./cmake_variables.hpp.in" "./cmake_variables.hpp" @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(rebootping_lib limited_pcap_dumper.hpp env.hpp space_estimate_for_path.cpp space_estimate_for_path.hpp file_contents_cache.cpp file_contents_cache.hpp event_tracker.cpp event_tracker.hpp now_unixtime.hpp str.hpp network_interface_watcher.cpp network_interface_watcher.hpp wire_layout.hpp ping_record_store.cpp ping_record_store.hpp wire_layout.cpp network_interface_watcher.cpp network_interfaces_manager.cpp network_interfaces_manager.hpp make_unique_ptr_closer.hpp call_errno.hpp flat_mmap.cpp flat_mmap.hpp flat_file_string.hpp flat_file_string_pool.cpp flat_file_string_pool.hpp flat_dirtree.cpp flat_dirtree.hpp flat_bytes_field.hpp escape_json.cpp
        flat_hash.hpp flat_cache.hpp rebootping_records_dir.cpp rebootping_records_dir.hpp network_flat_records.hpp
        network_flat_records.cpp thread_context.hpp thread_context.cpp flat_index_field.hpp flat_mfu_mru.hpp ping_health_decider.cpp ping_health_decider.hpp rebootping_report_html.cpp rebootping_report_html.hpp)

add_executable(rebootping rebootping_main.cpp)

enable_testing()
add_library(rebootping_test_lib rebootping_test.hpp rebootping_test_main.cpp)

target_include_directories(rebootping_lib PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(rebootping_lib ${PCAP_LIBRARY} Threads::Threads stdc++fs)
target_link_libraries(rebootping rebootping_lib)
target_link_libraries(rebootping_test_lib rebootping_lib)

add_executable(flat_mfu_mru_test flat_mfu_mru_test.cpp)
add_test(NAME flat_mfu_mru_test_name COMMAND flat_mfu_mru_test)
target_link_libraries(flat_mfu_mru_test rebootping_test_lib)

add_executable(flat_index_field_test flat_index_field_test.cpp)
add_test(NAME flat_index_field_test_name COMMAND flat_index_field_test)
target_link_libraries(flat_index_field_test rebootping_test_lib)

add_executable(rebootping_mmap_test rebootping_mmap_test.cpp)
add_test(NAME rebootping_mmap_test_name COMMAND rebootping_mmap_test)
target_link_libraries(rebootping_mmap_test rebootping_test_lib)

add_executable(network_interface_watcher_test network_interface_watcher_test.cpp)
add_test(NAME network_interface_watcher_test_name COMMAND network_interface_watcher_test
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(network_interface_watcher_test rebootping_test_lib)
