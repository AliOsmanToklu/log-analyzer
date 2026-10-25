import argparse
import csv

from .detectors import detect_bruteforce, detect_compromise, detect_scanners
from .parsers import parse_file, parse_windows_csv


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='log-analyzer',
        description="Detect brute force and scanning activity in SSH and Windows logon logs")
    ap.add_argument('file', help="Log file to analyze (.csv = Windows export, otherwise SSH auth log)")
    ap.add_argument('--threshold', type=int, default=10,
                    help="Failed attempts within the window that count as brute force (default: 10)")
    ap.add_argument('--window', type=int, default=60,
                    help="Sliding window length in seconds (default: 60)")
    ap.add_argument('--output', default='report.csv', help="CSV report path (default: report.csv)")
    args = ap.parse_args(argv)

    if args.file.lower().endswith('.csv'):
        events = parse_windows_csv(args.file)
    else:
        events = parse_file(args.file)
    print(f"=== Log Analysis: {args.file} ===")
    print(f"Total events: {len(events)}\n")

    suspects = detect_bruteforce(events, args.threshold, args.window)
    compromised = detect_compromise(events, suspects)
    scanners = detect_scanners(events)

    rows = []

    print("--- Brute Force Suspects ---")
    if not suspects:
        print("None found.")
    for ip, info in suspects.items():
        print(f"[!] {ip}: {info['total_failed']} failed attempts "
              f"(max {info['max_in_window']} within {args.window}s)")
        print(f"    Users tried: {', '.join(info['users_tried'])}")
        rows.append([ip, 'BRUTE_FORCE', 'HIGH',
                     f"{info['total_failed']} failed attempts"])

    print("\n--- CRITICAL: Successful Login After Brute Force ---")
    if not compromised:
        print("None found.")
    for e in compromised:
        print(f"[!!!] {e['ip']} -> logged in as '{e['user']}' ({e['time']})")
        rows.append([e['ip'], 'POSSIBLE_COMPROMISE', 'CRITICAL',
                     f"successful login as {e['user']}"])

    print("\n--- Slow Scan Suspects ---")
    if not scanners:
        print("None found.")
    for ip, info in scanners.items():
        print(f"[!] {ip}: {info['count']} invalid user attempts "
              f"({', '.join(info['users_tried'])})")
        rows.append([ip, 'SLOW_SCAN', 'MEDIUM',
                     f"{info['count']} invalid user attempts"])

    with open(args.output, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'Detection', 'Severity', 'Details'])
        writer.writerows(rows)

    print(f"\nReport saved: {args.output}")


if __name__ == '__main__':
    main()
