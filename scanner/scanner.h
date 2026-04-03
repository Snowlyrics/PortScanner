#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <functional>
#include <atomic>

enum class ScanMode {
    TCP,
    UDP,
    BOTH
};

struct ScanResult {
    int port;
    bool open;
    std::string protocol;   // "tcp" | "udp"
    std::string state;      // tcp: open/closed/filtered/error, udp: open/closed/open|filtered/error
    std::string service;    // guessed or confirmed service name
    std::string banner;     // captured banner if available
    bool service_confident; // true if based on actual response or strong probe match
};

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads);
    ~ThreadPool();

    void enqueue(std::function<void()> task);
    void wait();

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable cv;
    std::condition_variable cv_done;
    std::atomic<bool> stop{false};
    std::atomic<int> active{0};

    void worker_loop();
};

class PortScanner {
public:
    PortScanner(const std::string& target,
                int start_port,
                int end_port,
                int timeout_ms = 1000,
                int num_threads = 100,
                ScanMode mode = ScanMode::TCP,
                bool show_closed = false,
                bool show_udp_open_filtered = false);

    void run();
    const std::vector<ScanResult>& results() const { return results_; }
    void write_json(const std::string& filepath) const;

private:
    std::string target_;
    int start_port_;
    int end_port_;
    int timeout_ms_;
    int num_threads_;
    ScanMode mode_;
    bool show_closed_;
    bool show_udp_open_filtered_;

    std::vector<ScanResult> results_;
    std::mutex results_mutex_;

    ScanResult scan_tcp_port(int port);
    ScanResult scan_udp_port(int port);
};
