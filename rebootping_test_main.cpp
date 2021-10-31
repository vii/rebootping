#include "env.hpp"
#include "rebootping_test.hpp"

#include <functional>
#include <iostream>
#include <vector>


std::vector<std::pair<std::string, std::function<void()>>> &rebootping_tests() {
    static std::vector<std::pair<std::string, std::function<void()>>> _;
    return _;
}
std::vector<std::string> rebootping_test_failures;

int main() {
    std::cout << "rebpootping_test_main" << std::endl;
    for (auto &[name, f] : rebootping_tests()) {
        std::cout << "rebooting_running_test " << name << std::endl;
        try {
            f();
        } catch (std::exception const &e) {
            rebootping_test_fail("test_exception in ", name, ": ", e.what());
        } catch (...) {
            rebootping_test_fail("test_exception unknown_exception in ", name);
            throw;
        }
        std::cout << "rebootping_test_done " << name << std::endl;
    }
    if (!rebootping_test_failures.empty()) {
        std::cerr << "rebootping_test_failures " << rebootping_test_failures.size() << std::endl;
        return 17;
    } else {
        std::cout << "rebpootping_test_main all passed!" << std::endl;
    }
    return 0;
}