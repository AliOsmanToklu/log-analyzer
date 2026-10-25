from collections import defaultdict
from datetime import timedelta


def detect_bruteforce(events, threshold=10, window_seconds=60):
    """Find IPs with at least `threshold` failed attempts within the time window."""
    failed_by_ip = defaultdict(list)
    for e in events:
        if e['type'] == 'failed':
            failed_by_ip[e['ip']].append(e)

    window = timedelta(seconds=window_seconds)
    suspects = {}

    for ip, attempts in failed_by_ip.items():
        attempts.sort(key=lambda e: e['time'])

        # Sliding window: the largest number of attempts that fit in one window
        start = 0
        best = 0
        for end in range(len(attempts)):
            while attempts[end]['time'] - attempts[start]['time'] > window:
                start += 1
            best = max(best, end - start + 1)

        if best >= threshold:
            suspects[ip] = {
                'total_failed': len(attempts),
                'max_in_window': best,
                'first_seen': attempts[0]['time'],
                'last_seen': attempts[-1]['time'],
                'users_tried': sorted({a['user'] for a in attempts}),
            }

    return suspects


def detect_compromise(events, suspects):
    """Check whether a brute force suspect later logged in successfully."""
    compromised = []
    for e in events:
        if e['type'] == 'accepted' and e['ip'] in suspects:
            if e['time'] >= suspects[e['ip']]['first_seen']:
                compromised.append(e)
    return compromised


def detect_scanners(events, threshold=3):
    """Find IPs probing non-existent usernames (slow scanning)."""
    invalid_by_ip = defaultdict(list)
    for e in events:
        if e['type'] == 'invalid':
            invalid_by_ip[e['ip']].append(e)

    scanners = {}
    for ip, attempts in invalid_by_ip.items():
        if len(attempts) >= threshold:
            scanners[ip] = {
                'count': len(attempts),
                'users_tried': sorted({a['user'] for a in attempts}),
            }
    return scanners
