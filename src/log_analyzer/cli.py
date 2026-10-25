import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .analysis import AnalysisResult, analyze
from .models import Event
from .parsers import parse_file, parse_windows_csv
from .report import write_csv, write_json

EXIT_OK = 0
EXIT_ERROR = 2  # same code argparse uses for usage errors


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}") from None
    if number < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {number}")
    return number


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Detect brute force and scanning activity in SSH and Windows logon logs",
    )
    ap.add_argument("file", help="Log file to analyze")
    ap.add_argument(
        "--format",
        choices=["auto", "ssh", "windows"],
        default="auto",
        help="Input format; auto treats .csv as a Windows logon export and anything else "
        "as an SSH auth log (default: auto)",
    )
    ap.add_argument(
        "--threshold",
        type=positive_int,
        default=10,
        help="Failed attempts within the window that count as brute force (default: 10)",
    )
    ap.add_argument(
        "--window",
        type=positive_int,
        default=60,
        help="Sliding window length in seconds (default: 60)",
    )
    ap.add_argument(
        "--scan-threshold",
        type=positive_int,
        default=3,
        help="Invalid-user attempts from one IP that count as a slow scan (default: 3)",
    )
    ap.add_argument(
        "--year",
        type=int,
        help="Year of a classic syslog file, which has none in its timestamps "
        "(default: guessed so the log does not end in the future)",
    )
    ap.add_argument(
        "--output",
        default="report.csv",
        help="Report path; a .json extension writes a detailed JSON report, "
        "anything else a CSV (default: report.csv)",
    )
    return ap


def load_events(path: str, fmt: str, year: int | None) -> list[Event]:
    if fmt == "auto":
        fmt = "windows" if path.lower().endswith(".csv") else "ssh"
    if fmt == "windows":
        return parse_windows_csv(path)
    return parse_file(path, year)


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


def error(message: object) -> int:
    print(f"log-analyzer: error: {message}", file=sys.stderr)
    return EXIT_ERROR


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        events = load_events(args.file, args.format, args.year)
    except (OSError, ValueError) as exc:
        return error(exc)
    print(f"=== Log Analysis: {args.file} ===")

    result = analyze(events, args.threshold, args.window, args.scan_threshold)
    print_result(result)

    try:
        if Path(args.output).suffix.lower() == ".json":
            write_json(result, args.file, args.output)
        else:
            write_csv(result.findings(), args.output)
    except OSError as exc:
        return error(exc)
    print(f"\nReport saved: {args.output}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
