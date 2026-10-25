import csv
import random
from datetime import datetime, timedelta

random.seed(7)

start = datetime(2026, 10, 25, 9, 0, 0)
rows = []

# Normal başarılı girişler
for i in range(10):
    t = start + timedelta(minutes=random.randint(0, 480))
    rows.append([t, 4624, random.choice(['ahmet', 'ayse']), '192.168.1.20'])

# Yerel girişler (parser bunları elemeli)
for i in range(5):
    t = start + timedelta(minutes=random.randint(0, 480))
    rows.append([t, 4624, 'SYSTEM', '-'])

# Saldırgan: RDP üzerinden brute force, sonunda başarı
attacker = '203.0.113.99'
attack_start = start + timedelta(hours=4)
for i in range(30):
    t = attack_start + timedelta(seconds=i * 2)
    rows.append([t, 4625, random.choice(['administrator', 'admin', 'user1']), attacker])
rows.append([attack_start + timedelta(seconds=75), 4624, 'administrator', attacker])

rows.sort(key=lambda r: r[0])

with open('windows_events.csv', 'w', newline='', encoding='utf-8-sig') as f:
    writer = csv.writer(f)
    writer.writerow(['Time', 'Id', 'User', 'IP'])
    for t, event_id, user, ip in rows:
        writer.writerow([t.strftime('%Y-%m-%d %H:%M:%S'), event_id, user, ip])

print(f"windows_events.csv oluşturuldu: {len(rows)} satır")