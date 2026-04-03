#include "scanner.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <cstring>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>

ThreadPool::ThreadPool(size_t num_threads) {
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back([this] { worker_loop(); });
    }
}

ThreadPool::~ThreadPool() {
    stop = true;
    cv.notify_all();
    for (auto& w : workers) {
        if (w.joinable()) {
            w.join();
        }
    }
}

void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        tasks.push(std::move(task));
    }
    cv.notify_one();
}

void ThreadPool::wait() {
    std::unique_lock<std::mutex> lock(queue_mutex);
    cv_done.wait(lock, [this] {
        return tasks.empty() && active.load() == 0;
    });
}

void ThreadPool::worker_loop() {
    while (true) {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            cv.wait(lock, [this] { return stop || !tasks.empty(); });

            if (stop && tasks.empty()) {
                return;
            }

            task = std::move(tasks.front());
            tasks.pop();
        }

        ++active;
        task();
        --active;

        cv_done.notify_all();
    }
}

static std::string resolve_host_ipv4(const std::string& host) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) {
        return host;
    }

    char ip[INET_ADDRSTRLEN] = {0};
    auto* addr = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &(addr->sin_addr), ip, sizeof(ip));
    freeaddrinfo(res);

    return std::string(ip);
}

static std::string guess_tcp_service_from_port(int port) {
    switch (port) {
    case 20: return "FTP-Data";
    case 21: return "FTP";
    case 22: return "SSH";
    case 23: return "Telnet";
    case 25: return "SMTP";
    case 53: return "DNS";
    case 80: return "HTTP";
    case 110: return "POP3";
    case 143: return "IMAP";
    case 443: return "HTTPS";
    case 445: return "SMB";
    case 587: return "SMTP-Submission";
    case 993: return "IMAPS";
    case 995: return "POP3S";
    case 3306: return "MySQL";
    case 3389: return "RDP";
    case 5432: return "PostgreSQL";
    case 6379: return "Redis";
    case 8000: return "HTTP-Alt";
    case 8080: return "HTTP-Proxy";
    case 8443: return "HTTPS-Alt";
    default: return "unknown";
    }
}

static std::string guess_udp_service_from_port(int port) {
    switch (port) {
    case 53: return "DNS";
    case 67: return "DHCP";
    case 68: return "DHCP";
    case 69: return "TFTP";
    case 123: return "NTP";
    case 137: return "NetBIOS-NS";
    case 138: return "NetBIOS-DGM";
    case 161: return "SNMP";
    case 162: return "SNMP-Trap";
    case 514: return "Syslog";
    default: return "unknown";
    }
}

static std::string trim_banner(const std::string& input) {
    std::string out;
    out.reserve(input.size());

    for (unsigned char c : input) {
        if (c == '\r' || c == '\n' || c == '\t') {
            out.push_back(' ');
        } else if (c >= 32 && c <= 126) {
            out.push_back(static_cast<char>(c));
        }
    }

    while (!out.empty() && out.front() == ' ') out.erase(out.begin());
    while (!out.empty() && out.back() == ' ') out.pop_back();

    std::string collapsed;
    collapsed.reserve(out.size());
    bool prev_space = false;
    for (char c : out) {
        if (c == ' ') {
            if (!prev_space) collapsed.push_back(c);
            prev_space = true;
        } else {
            collapsed.push_back(c);
            prev_space = false;
        }
    }

    if (collapsed.size() > 160) {
        collapsed = collapsed.substr(0, 160) + "...";
    }

    return collapsed;
}

static std::string recv_with_timeout(int sock, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int sel = select(sock + 1, &rfds, nullptr, nullptr, &tv);
    if (sel <= 0) {
        return "";
    }

    char buf[1024];
    ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        return "";
    }

    return trim_banner(std::string(buf, n));
}

static std::string send_probe_and_recv(int sock, const std::string& probe, int timeout_ms) {
    ssize_t sent = send(sock, probe.c_str(), probe.size(), 0);
    if (sent < 0) {
        return "";
    }
    return recv_with_timeout(sock, timeout_ms);
}

static std::string grab_tcp_banner(int sock, int port, int timeout_ms, const std::string& host) {
    std::string banner = recv_with_timeout(sock, 400);
    if (!banner.empty()) {
        return banner;
    }

    if (port == 80 || port == 8000 || port == 8080 || port == 8443) {
        std::string probe =
            "HEAD / HTTP/1.0\r\n"
            "Host: " + host + "\r\n"
                     "User-Agent: PortScanner/0.1\r\n"
                     "\r\n";
        return send_probe_and_recv(sock, probe, timeout_ms);
    }

    if (port == 6379) {
        return send_probe_and_recv(sock, "PING\r\n", timeout_ms);
    }

    if (port == 25 || port == 587) {
        return send_probe_and_recv(sock, "EHLO scanner.local\r\n", timeout_ms);
    }

    return "";
}

static std::string build_udp_payload_for_port(int port) {
    switch (port) {
    case 53:
        return std::string(
            "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            "\x07version\x04bind\x00\x00\x10\x00\x03",
            30
            );
    case 123:
        return std::string("\x1b", 1);
    case 161:
        return std::string(
            "\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04"
            "\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x00\x30\x0b\x30"
            "\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
            40
            );
    case 69:
        return std::string("\x00\x01test\x00octet\x00", 13);
    default:
        return "";
    }
}

static std::string json_escape(const std::string& s) {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
        case '\"': oss << "\\\""; break;
        case '\\': oss << "\\\\"; break;
        case '\b': oss << "\\b"; break;
        case '\f': oss << "\\f"; break;
        case '\n': oss << "\\n"; break;
        case '\r': oss << "\\r"; break;
        case '\t': oss << "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                oss << "\\u"
                    << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(c));
            } else {
                oss << c;
            }
        }
    }
    return oss.str();
}

PortScanner::PortScanner(const std::string& target,
                         int start_port,
                         int end_port,
                         int timeout_ms,
                         int num_threads,
                         ScanMode mode,
                         bool show_closed,
                         bool show_udp_open_filtered)
    : target_(target),
    start_port_(start_port),
    end_port_(end_port),
    timeout_ms_(timeout_ms),
    num_threads_(num_threads),
    mode_(mode),
    show_closed_(show_closed),
    show_udp_open_filtered_(show_udp_open_filtered) {}

ScanResult PortScanner::scan_tcp_port(int port) {
    ScanResult result{
        port, false, "tcp", "closed",
        guess_tcp_service_from_port(port), "", false
    };

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        result.state = "error";
        return result;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        close(sock);
        result.state = "error";
        return result;
    }

    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sock);
        result.state = "error";
        return result;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (inet_pton(AF_INET, target_.c_str(), &addr.sin_addr) != 1) {
        close(sock);
        result.state = "error";
        return result;
    }

    int rc = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

    if (rc == 0) {
        result.open = true;
        result.state = "open";
    } else if (errno == EINPROGRESS) {
        fd_set wfds, efds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        FD_ZERO(&efds);
        FD_SET(sock, &efds);

        timeval tv{};
        tv.tv_sec = timeout_ms_ / 1000;
        tv.tv_usec = (timeout_ms_ % 1000) * 1000;

        int sel = select(sock + 1, nullptr, &wfds, &efds, &tv);

        if (sel > 0 && FD_ISSET(sock, &wfds)) {
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0) {
                if (err == 0) {
                    result.open = true;
                    result.state = "open";
                } else if (err == ECONNREFUSED) {
                    result.state = "closed";
                } else {
                    result.state = "filtered";
                }
            } else {
                result.state = "error";
            }
        } else if (sel == 0) {
            result.state = "filtered";
        } else {
            result.state = "error";
        }
    } else if (errno == ECONNREFUSED) {
        result.state = "closed";
    } else {
        result.state = "filtered";
    }

    if (result.open) {
        int blocking_flags = fcntl(sock, F_GETFL, 0);
        if (blocking_flags >= 0) {
            fcntl(sock, F_SETFL, blocking_flags & ~O_NONBLOCK);
        }

        result.banner = grab_tcp_banner(sock, port, timeout_ms_, target_);
        result.service_confident = result.banner.empty() ? (result.service != "unknown") : true;
    }

    close(sock);
    return result;
}

ScanResult PortScanner::scan_udp_port(int port) {
    ScanResult result{
        port, false, "udp", "open|filtered",
        "unknown", "", false
    };

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        result.state = "error";
        return result;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (inet_pton(AF_INET, target_.c_str(), &addr.sin_addr) != 1) {
        close(sock);
        result.state = "error";
        return result;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sock);
        result.state = "error";
        return result;
    }

    std::string payload = build_udp_payload_for_port(port);
    if (payload.empty()) {
        payload = "\x00";
    }

    ssize_t sent = send(sock, payload.data(), payload.size(), 0);
    if (sent < 0) {
        if (errno == ECONNREFUSED) {
            result.state = "closed";
        } else {
            result.state = "error";
        }
        close(sock);
        return result;
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);

    timeval tv{};
    tv.tv_sec = timeout_ms_ / 1000;
    tv.tv_usec = (timeout_ms_ % 1000) * 1000;

    int sel = select(sock + 1, &rfds, nullptr, nullptr, &tv);

    if (sel > 0 && FD_ISSET(sock, &rfds)) {
        char buf[1024];
        ssize_t n = recv(sock, buf, sizeof(buf), 0);

        if (n > 0) {
            result.open = true;
            result.state = "open";
            result.banner = trim_banner(std::string(buf, n));
            result.service = guess_udp_service_from_port(port);
            result.service_confident = true;
        } else if (n < 0 && errno == ECONNREFUSED) {
            result.state = "closed";
        }
    } else if (sel == 0) {
        result.state = "open|filtered";
        result.service = "unknown";
        result.service_confident = false;
    } else {
        if (errno == ECONNREFUSED) {
            result.state = "closed";
        } else {
            result.state = "error";
        }
    }

    close(sock);
    return result;
}

void PortScanner::run() {
    std::string resolved = resolve_host_ipv4(target_);
    if (resolved != target_) {
        std::cout << "[*] Resolved " << target_ << " -> " << resolved << "\n";
        target_ = resolved;
    }

    int total_ports = end_port_ - start_port_ + 1;
    std::string mode_str =
        (mode_ == ScanMode::TCP ? "tcp" :
             (mode_ == ScanMode::UDP ? "udp" : "both"));

    std::cout << "[*] Scanning " << target_
              << " ports " << start_port_ << "-" << end_port_
              << " (" << total_ports << " ports, "
              << num_threads_ << " threads, "
              << timeout_ms_ << "ms timeout, mode=" << mode_str << ")\n";

    auto t_start = std::chrono::steady_clock::now();
    ThreadPool pool(static_cast<size_t>(num_threads_));

    for (int port = start_port_; port <= end_port_; ++port) {
        if (mode_ == ScanMode::TCP || mode_ == ScanMode::BOTH) {
            pool.enqueue([this, port] {
                ScanResult r = scan_tcp_port(port);
                bool keep = r.open || r.state == "filtered" || show_closed_;
                if (keep) {
                    std::lock_guard<std::mutex> lock(results_mutex_);
                    results_.push_back(std::move(r));
                }
            });
        }

        if (mode_ == ScanMode::UDP || mode_ == ScanMode::BOTH) {
            pool.enqueue([this, port] {
                ScanResult r = scan_udp_port(port);
                bool keep = r.open || show_closed_ ||
                            (show_udp_open_filtered_ && r.state == "open|filtered");
                if (keep) {
                    std::lock_guard<std::mutex> lock(results_mutex_);
                    results_.push_back(std::move(r));
                }
            });
        }
    }

    pool.wait();

    std::sort(results_.begin(), results_.end(),
              [](const ScanResult& a, const ScanResult& b) {
                  if (a.port == b.port) return a.protocol < b.protocol;
                  return a.port < b.port;
              });

    auto t_end = std::chrono::steady_clock::now();
    double secs = std::chrono::duration<double>(t_end - t_start).count();

    int open_count = 0;
    int filtered_count = 0;
    int open_filtered_count = 0;
    int closed_count = 0;

    for (const auto& r : results_) {
        if (r.state == "open") ++open_count;
        else if (r.state == "filtered") ++filtered_count;
        else if (r.state == "open|filtered") ++open_filtered_count;
        else if (r.state == "closed") ++closed_count;
    }

    std::cout << "[+] Done in " << secs << "s — "
              << open_count << " open, "
              << filtered_count << " filtered";
    if (show_udp_open_filtered_) {
        std::cout << ", " << open_filtered_count << " open|filtered";
    }
    if (show_closed_) {
        std::cout << ", " << closed_count << " closed";
    }
    std::cout << "\n\n";

    std::cout << std::left
              << std::setw(8)  << "PORT"
              << std::setw(8)  << "PROTO"
              << std::setw(16) << "STATE"
              << std::setw(16) << "SERVICE"
              << "BANNER\n";
    std::cout << std::string(110, '-') << "\n";

    for (const auto& r : results_) {
        std::string service_display = r.service;
        if (!r.service_confident && r.protocol == "udp" && r.state == "open|filtered") {
            service_display = "unknown";
        }

        std::cout << std::left
                  << std::setw(8)  << r.port
                  << std::setw(8)  << r.protocol
                  << std::setw(16) << r.state
                  << std::setw(16) << service_display
                  << (r.banner.empty() ? "-" : r.banner)
                  << "\n";
    }

    if ((mode_ == ScanMode::UDP || mode_ == ScanMode::BOTH) && show_udp_open_filtered_) {
        std::cout << "\n[!] UDP open|filtered means no reply was received; this is inconclusive and may indicate either an open UDP service or packet filtering.\n";
    }
}

void PortScanner::write_json(const std::string& filepath) const {
    std::ofstream f(filepath);
    if (!f) {
        std::cerr << "[-] Cannot write to " << filepath << "\n";
        return;
    }

    f << "{\n";
    f << "  \"target\": \"" << json_escape(target_) << "\",\n";
    f << "  \"port_range\": [" << start_port_ << ", " << end_port_ << "],\n";
    f << "  \"results\": [\n";

    for (size_t i = 0; i < results_.size(); ++i) {
        const auto& r = results_[i];
        f << "    {\n";
        f << "      \"port\": " << r.port << ",\n";
        f << "      \"protocol\": \"" << json_escape(r.protocol) << "\",\n";
        f << "      \"open\": " << (r.open ? "true" : "false") << ",\n";
        f << "      \"state\": \"" << json_escape(r.state) << "\",\n";
        f << "      \"service\": \"" << json_escape(r.service) << "\",\n";
        f << "      \"service_confident\": " << (r.service_confident ? "true" : "false") << ",\n";
        f << "      \"banner\": \"" << json_escape(r.banner) << "\"\n";
        f << "    }";
        if (i + 1 < results_.size()) {
            f << ",";
        }
        f << "\n";
    }

    f << "  ]\n";
    f << "}\n";

    std::cout << "[+] Results saved to " << filepath << "\n";
}
