import argparse
from collections.abc import Sequence

from .analysis import AnalysisResult, analyze
from .parsers import parse_file, parse_windows_csv
from .report import write_csv


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Detect brute force and scanning activity in SSH and Windows logon logs",
    )
    ap.add_argument(
        "file", help="Log file to analyze (.csv = Windows export, otherwise SSH auth log)"
    )
    ap.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Failed attempts within the window that count as brute force (default: 10)",
    )
    ap.add_argument(
        "--window", type=int, default=60, help="Sliding window length in seconds (default: 60)"
    )
    ap.add_argument("--output", default="report.csv", help="CSV report path (default: report.csv)")
    ap.add_argument(
        "--year",
        type=int,
        help="Year of a classic syslog file, which has none in its timestamps "
        "(default: guessed so the log does not end in the future)",
    )
    return ap


def print_result(result: AnalysisResult) -> None:
    print(f"Total events: {result.total_events}\n")

    print("--- Brute Force Suspects ---")
    if not result.bruteforce:
        print("None found.")
    for s in result.bruteforce:
        print(
            f"[!] {s.ip}: {s.total_failed} failed attempts "
            f"(max {s.max_in_window} within {result.window_seconds}s)"
        )
        print(f"    Users tried: {', '.join(s.users_tried)}")

    print("\n--- CRITICAL: Successful Login After Brute Force ---")
    if not result.compromises:
        print("None found.")
    for e in result.compromises:
        print(f"[!!!] {e.ip} -> logged in as '{e.user}' ({e.time})")

    print("\n--- Slow Scan Suspects ---")
    if not result.scanners:
        print("None found.")
    for sc in result.scanners:
        print(f"[!] {sc.ip}: {sc.count} invalid user attempts ({', '.join(sc.users_tried)})")


def main(argv: Sequence[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    if args.file.lower().endswith(".csv"):
        events = parse_windows_csv(args.file)
    else:
        events = parse_file(args.file, args.year)
    print(f"=== Log Analysis: {args.file} ===")

    result = analyze(events, args.threshold, args.window)
    print_result(result)

    write_csv(result.findings(), args.output)
    print(f"\nReport saved: {args.output}")


if __name__ == "__main__":
    main()
