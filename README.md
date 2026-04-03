# PortScanner

A multithreaded port scanner written in C++ with a Python CLI wrapper for cleaner output and easier usage.

## Features

- TCP connect scanning.
- Basic banner grabbing for open TCP services.
- Basic UDP scanning.
- JSON output for automation.
- Python wrapper with `rich` for formatted terminal output.

## Tech Stack

- C++ for the scanning engine.
- Python for the CLI wrapper and output formatting.

## Project Structure

```text
PortScanner/
├── scanner/
│   ├── scanner.h
│   ├── scanner.cpp
│   ├── main.cpp
│   └── Makefile
├── cli/
│   └── scan.py
├── output/
├── README.md
├── .gitignore
└── LICENSE
```

## Build

### C++ scanner

```bash
cd scanner
make
```

### Python wrapper dependency

On Arch Linux:

```bash
sudo pacman -S python-rich
```

Or with a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install rich
```

## Usage

### Run the C++ scanner directly

```bash
./PortScanner 127.0.0.1 1 1024
./PortScanner 127.0.0.1 8000 8000
./PortScanner 127.0.0.1 1 200 --mode both --show-udp-ambiguous
```

### Run the Python wrapper

```bash
python3 scan.py 127.0.0.1 8000 8000 --mode tcp --scanner-bin ./PortScanner
```

## Example

Start a local HTTP server:

```bash
python3 -m http.server 8000
```

Then scan it:

```bash
./PortScanner 127.0.0.1 8000 8000
python3 scan.py 127.0.0.1 8000 8000 --mode tcp --scanner-bin ./PortScanner
```

## Limitations

- UDP results may be ambiguous (`open|filtered`).
- Service detection is basic.
- Banner grabbing is limited to simple probes.
- This project is educational and does not aim to replace Nmap.

## Ethical Use

This tool is for authorized testing and educational use only.

Only scan systems you own or have explicit permission to test.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
