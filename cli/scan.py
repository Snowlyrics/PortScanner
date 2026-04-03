#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.json import JSON
except ImportError:
    print("[-] Missing dependency: rich")
    print("[*] Install it with: pip install rich")
    sys.exit(1)


console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Python CLI wrapper for the C++ PortScanner"
    )

    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("start_port", type=int, help="Start of port range")
    parser.add_argument("end_port", type=int, help="End of port range")

    parser.add_argument(
        "--mode",
        choices=["tcp", "udp", "both"],
        default="tcp",
        help="Scan mode (default: tcp)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1000,
        help="Timeout in milliseconds (default: 1000)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of threads (default: 100)",
    )
    parser.add_argument(
        "--scanner-bin",
        default="../scanner/PortScanner",
        help="Path to compiled C++ scanner binary (default: ../scanner/PortScanner)",
    )
    parser.add_argument(
        "--output",
        help="Write JSON results to this file",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Include closed ports in scanner output",
    )
    parser.add_argument(
        "--show-udp-ambiguous",
        action="store_true",
        help="Include UDP open|filtered results",
    )
    parser.add_argument(
        "--proto-filter",
        choices=["tcp", "udp"],
        help="Only display one protocol from the JSON results",
    )
    parser.add_argument(
        "--state-filter",
        choices=["open", "filtered", "open|filtered", "closed", "error"],
        help="Only display one state from the JSON results",
    )
    parser.add_argument(
        "--pretty-json",
        action="store_true",
        help="Also pretty-print the raw JSON output",
    )

    return parser


def resolve_scanner_binary(path_str: str) -> Path:
    given = Path(path_str)

    if given.exists():
        return given.resolve()

    script_dir = Path(__file__).resolve().parent
    candidate = (script_dir / path_str).resolve()
    if candidate.exists():
        return candidate

    alt = (script_dir / "../scanner/scanner").resolve()
    if alt.exists():
        return alt

    alt2 = (script_dir / "../scanner/PortScanner").resolve()
    if alt2.exists():
        return alt2

    console.print(f"[red][-] Could not find scanner binary:[/] {path_str}")
    console.print("[yellow][*] Expected something like:[/] ../scanner/scanner")
    sys.exit(1)


def run_scanner(args, json_output_path: Path, scanner_bin: Path) -> None:
    cmd = [
        str(scanner_bin),
        args.target,
        str(args.start_port),
        str(args.end_port),
        "--mode",
        args.mode,
        "--timeout",
        str(args.timeout),
        "--threads",
        str(args.threads),
        "--output",
        str(json_output_path),
    ]

    if args.show_closed:
        cmd.append("--show-closed")
    if args.show_udp_ambiguous:
        cmd.append("--show-udp-ambiguous")

    console.print(Panel.fit(
        f"[bold]Running scanner[/bold]\n[cyan]{' '.join(cmd)}[/cyan]",
        border_style="blue"
    ))

    try:
        result = subprocess.run(cmd, check=False, text=True, capture_output=True)
    except FileNotFoundError:
        console.print(f"[red][-] Scanner binary not found:[/] {scanner_bin}")
        sys.exit(1)

    if result.stdout.strip():
        console.print(Panel(result.stdout.strip(), title="Scanner Output", border_style="green"))

    if result.stderr.strip():
        console.print(Panel(result.stderr.strip(), title="Scanner Errors", border_style="red"))

    if result.returncode != 0:
        console.print(f"[red][-] Scanner exited with code {result.returncode}[/]")
        sys.exit(result.returncode)


def load_results(json_path: Path) -> dict:
    if not json_path.exists():
        console.print(f"[red][-] JSON output file was not created:[/] {json_path}")
        sys.exit(1)

    try:
        return json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        console.print(f"[red][-] Failed to parse JSON:[/] {exc}")
        sys.exit(1)


def filter_results(results: list, proto_filter: str | None, state_filter: str | None) -> list:
    filtered = results

    if proto_filter:
        filtered = [r for r in filtered if r.get("protocol") == proto_filter]

    if state_filter:
        filtered = [r for r in filtered if r.get("state") == state_filter]

    return filtered


def make_results_table(results: list, target: str, port_range: list) -> Table:
    table = Table(
        title=f"Scan Results for {target} ({port_range[0]}-{port_range[1]})",
        header_style="bold magenta",
        show_lines=False
    )

    table.add_column("Port", justify="right", style="cyan", no_wrap=True)
    table.add_column("Proto", style="white")
    table.add_column("State", style="white")
    table.add_column("Service", style="green")
    table.add_column("Confident", style="yellow")
    table.add_column("Banner", style="white", overflow="fold")

    for r in results:
        state = r.get("state", "")
        if state == "open":
            state_display = "[bold green]open[/]"
        elif state == "filtered":
            state_display = "[yellow]filtered[/]"
        elif state == "open|filtered":
            state_display = "[bold yellow]open|filtered[/]"
        elif state == "closed":
            state_display = "[red]closed[/]"
        else:
            state_display = f"[dim]{state}[/]"

        confident = "yes" if r.get("service_confident") else "no"
        banner = r.get("banner") or "-"
        service = r.get("service") or "unknown"

        table.add_row(
            str(r.get("port", "")),
            r.get("protocol", ""),
            state_display,
            service,
            confident,
            banner,
        )

    return table


def print_summary(results: list) -> None:
    counts = {}
    proto_counts = {"tcp": 0, "udp": 0}

    for r in results:
        state = r.get("state", "unknown")
        proto = r.get("protocol", "unknown")
        counts[state] = counts.get(state, 0) + 1
        if proto in proto_counts:
            proto_counts[proto] += 1

    summary_lines = [
        f"[green]Open:[/] {counts.get('open', 0)}",
        f"[yellow]Filtered:[/] {counts.get('filtered', 0)}",
        f"[yellow]Open|Filtered:[/] {counts.get('open|filtered', 0)}",
        f"[red]Closed:[/] {counts.get('closed', 0)}",
        f"[cyan]TCP rows:[/] {proto_counts.get('tcp', 0)}",
        f"[magenta]UDP rows:[/] {proto_counts.get('udp', 0)}",
    ]

    console.print(Panel("\n".join(summary_lines), title="Summary", border_style="cyan"))


def maybe_copy_output(temp_json: Path, requested_output: str | None) -> None:
    if requested_output:
        dst = Path(requested_output)
        dst.write_text(temp_json.read_text(encoding="utf-8"), encoding="utf-8")
        console.print(f"[green][+] Saved JSON to[/] {dst}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.start_port < 1 or args.end_port > 65535 or args.start_port > args.end_port:
        console.print("[red][-] Invalid port range[/]")
        sys.exit(1)

    if args.threads < 1 or args.threads > 1000:
        console.print("[red][-] Thread count must be between 1 and 1000[/]")
        sys.exit(1)

    scanner_bin = resolve_scanner_binary(args.scanner_bin)

    with tempfile.TemporaryDirectory() as tmpdir:
        temp_json = Path(tmpdir) / "scan_results.json"

        run_scanner(args, temp_json, scanner_bin)
        data = load_results(temp_json)
        maybe_copy_output(temp_json, args.output)

        results = data.get("results", [])
        filtered_results = filter_results(results, args.proto_filter, args.state_filter)

        print_summary(filtered_results)

        if filtered_results:
            table = make_results_table(
                filtered_results,
                data.get("target", args.target),
                data.get("port_range", [args.start_port, args.end_port]),
            )
            console.print(table)
        else:
            console.print("[yellow][*] No results matched the selected filters.[/]")

        if args.pretty_json:
            console.print(Panel(
                JSON.from_data(data),
                title="Raw JSON",
                border_style="white"
            ))


if __name__ == "__main__":
    main()
