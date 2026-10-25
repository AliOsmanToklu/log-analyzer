import re
from datetime import datetime

# Üç tür satırı yakalayan kalıplar
PATTERNS = {
    'failed': re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+)'),
    'accepted': re.compile(r'Accepted password for (\S+) from (\S+)'),
    'invalid': re.compile(r'Invalid user (\S+) from (\S+)'),
}


def parse_line(line, year=2026):
    """Bir log satırını sözlüğe çevirir. Tanınmayan satır için None döner."""
    time_str = line[:15]  # örn. "Oct 25 11:02:05"
    try:
        timestamp = datetime.strptime(f"{year} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if match:
            return {
                'time': timestamp,
                'type': event_type,
                'user': match.group(1),
                'ip': match.group(2),
            }
    return None


def parse_file(filepath):
    events = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


if __name__ == '__main__':
    events = parse_file('auth.log')
    print(f"{len(events)} olay ayrıştırıldı")
    for e in events[:5]:
        print(e)