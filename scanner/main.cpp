#include "scanner.h"

#include <iostream>
#include <string>
#include <cstdlib>

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " <target> <start_port> <end_port> [options]\n"
        << "\nArguments:\n"
        << "  target                  IP address or hostname to scan\n"
        << "  start_port              First port in range (1-65535)\n"
        << "  end_port                Last port in range  (1-65535)\n"
        << "\nOptions:\n"
        << "  --timeout <ms>          Timeout in milliseconds (default: 1000)\n"
        << "  --threads <n>           Number of threads (default: 100)\n"
        << "  --output <file>         Write JSON results to file\n"
        << "  --mode <m>              tcp | udp | both (default: tcp)\n"
        << "  --show-closed           Also print closed ports\n"
        << "  --show-udp-ambiguous    Also print UDP open|filtered ports\n"
        << "\nExamples:\n"
        << "  " << prog << " 127.0.0.1 1 1024\n"
        << "  " << prog << " 127.0.0.1 53 53 --mode udp --show-udp-ambiguous\n"
        << "  " << prog << " scanme.nmap.org 1 200 --mode both --output results.json\n"
        << "\n[!] Only scan hosts you own or have explicit permission to scan.\n";
}

static bool parse_mode(const std::string& s, ScanMode& mode) {
    if (s == "tcp") {
        mode = ScanMode::TCP;
        return true;
    }
    if (s == "udp") {
        mode = ScanMode::UDP;
        return true;
    }
    if (s == "both") {
        mode = ScanMode::BOTH;
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    std::string target = argv[1];
    int start_port = std::atoi(argv[2]);
    int end_port = std::atoi(argv[3]);
    int timeout_ms = 1000;
    int threads = 100;
    std::string output_file;
    ScanMode mode = ScanMode::TCP;
    bool show_closed = false;
    bool show_udp_open_filtered = false;

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];

        if ((arg == "--timeout" || arg == "-t") && i + 1 < argc) {
            timeout_ms = std::atoi(argv[++i]);
        } else if ((arg == "--threads" || arg == "-T") && i + 1 < argc) {
            threads = std::atoi(argv[++i]);
        } else if ((arg == "--output" || arg == "-o") && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--mode" && i + 1 < argc) {
            if (!parse_mode(argv[++i], mode)) {
                std::cerr << "[-] Invalid mode. Use tcp, udp, or both.\n";
                return 1;
            }
        } else if (arg == "--show-closed") {
            show_closed = true;
        } else if (arg == "--show-udp-ambiguous") {
            show_udp_open_filtered = true;
        } else {
            std::cerr << "[-] Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (start_port < 1 || end_port > 65535 || start_port > end_port) {
        std::cerr << "[-] Invalid port range: " << start_port << "-" << end_port << "\n";
        return 1;
    }

    if (threads < 1 || threads > 1000) {
        std::cerr << "[-] Thread count must be between 1 and 1000.\n";
        return 1;
    }

    PortScanner scanner(target, start_port, end_port, timeout_ms, threads,
                        mode, show_closed, show_udp_open_filtered);
    scanner.run();

    if (!output_file.empty()) {
        scanner.write_json(output_file);
    }

    return 0;
}
