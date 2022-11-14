#pragma once

#include <atomic>
#include <cstdint>
#include <thread>

class loop_thread {
  protected:
    virtual bool loop_run_once() = 0; // return true to stop
    inline virtual void loop_started() {}
    inline virtual void loop_stopped() {}

    inline void loop_spawn() {
        loop_std_thread = std::thread([&] {
            loop_started();
            while (!loop_should_stop.load()) {
                if (loop_run_once()) { loop_should_stop.store(true); }
                loop_count++;
            }

            try {
                loop_stopped();
            } catch (...) {
                loop_finished.store(true);
                throw;
            }
            loop_finished.store(true);
        });
    }
    loop_thread() = default;

  public:
    loop_thread(loop_thread const &) = delete;
    loop_thread &operator=(loop_thread const &) = delete;

    inline virtual ~loop_thread() { loop_stop_join(); }

    inline void loop_stop() { loop_should_stop.store(true); }
    [[nodiscard]] inline bool loop_is_stopping() const { return loop_should_stop.load(); }
    [[nodiscard]] inline bool loop_has_finished() const { return loop_finished.load(); }

  protected:
    void loop_stop_join() {
        loop_stop();
        if (loop_std_thread.joinable()) { loop_std_thread.join(); }
    }

  private:
    // would be reasonable to make this waitable not just a counter variable
    std::atomic<bool> loop_finished = false;
    std::atomic<bool> loop_should_stop = false;
    std::atomic<uint64_t> loop_count = 0;
    std::thread loop_std_thread;
};
