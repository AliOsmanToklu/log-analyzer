from collections import defaultdict
from datetime import timedelta


def detect_bruteforce(events, threshold=10, window_seconds=60):
    """Belirli süre içinde 'threshold' veya daha fazla başarısız deneme yapan IP'leri bulur."""
    failed_by_ip = defaultdict(list)
    for e in events:
        if e['type'] == 'failed':
            failed_by_ip[e['ip']].append(e)

    window = timedelta(seconds=window_seconds)
    suspects = {}

    for ip, attempts in failed_by_ip.items():
        attempts.sort(key=lambda e: e['time'])

        # Kayan pencere (sliding window): pencereye sığan en fazla deneme sayısı
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
    """Brute force şüphelisi bir IP'nin sonradan başarılı giriş yapıp yapmadığına bakar."""
    compromised = []
    for e in events:
        if e['type'] == 'accepted' and e['ip'] in suspects:
            if e['time'] >= suspects[e['ip']]['first_seen']:
                compromised.append(e)
    return compromised


def detect_scanners(events, threshold=3):
    """Geçersiz kullanıcı adı deneyen (yavaş tarama yapan) IP'leri bulur."""
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


if __name__ == '__main__':
    from parser import parse_file

    events = parse_file('auth.log')
    suspects = detect_bruteforce(events)
    print("Brute force şüphelileri:", suspects)
    print("Ele geçirme şüphesi:", detect_compromise(events, suspects))
    print("Yavaş tarayıcılar:", detect_scanners(events))