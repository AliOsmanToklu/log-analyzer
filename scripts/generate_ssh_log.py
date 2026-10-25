"""Generate a synthetic SSH auth.log with a known attack scenario."""

import random
import sys
from datetime import datetime, timedelta

output = sys.argv[1] if len(sys.argv) > 1 else "samples/auth.log"

random.seed(42)

normal_users = ["ahmet", "ayse", "mehmet"]
attacker_ip = "203.0.113.45"
normal_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
scanner_ip = "198.51.100.7"

start = datetime(2026, 10, 25, 8, 0, 0)
lines = []


def fmt(t):
    return t.strftime("%b %d %H:%M:%S")


# Normal successful logins
for i in range(15):
    t = start + timedelta(minutes=random.randint(0, 600))
    user = random.choice(normal_users)
    ip = random.choice(normal_ips)
    lines.append((t, f"{fmt(t)} server sshd[1234]: Accepted password for {user} from {ip} port 52000 ssh2"))

# Occasional wrong password (ordinary user mistakes)
for i in range(4):
    t = start + timedelta(minutes=random.randint(0, 600))
    user = random.choice(normal_users)
    ip = random.choice(normal_ips)
    lines.append((t, f"{fmt(t)} server sshd[1234]: Failed password for {user} from {ip} port 52000 ssh2"))

# Attacker: many attempts in a short time, finally succeeds
attack_start = start + timedelta(hours=3)
for i in range(40):
    t = attack_start + timedelta(seconds=i * 3)
    user = random.choice(["root", "admin", "test", "ubuntu", "ahmet"])
    lines.append((t, f"{fmt(t)} server sshd[1234]: Failed password for {user} from {attacker_ip} port 40000 ssh2"))
t = attack_start + timedelta(seconds=125)
lines.append((t, f"{fmt(t)} server sshd[1234]: Accepted password for ahmet from {attacker_ip} port 40000 ssh2"))

# Slow scanner: few attempts, invalid username
for i in range(6):
    t = start + timedelta(minutes=30 * i)
    lines.append((t, f"{fmt(t)} server sshd[1234]: Invalid user oracle from {scanner_ip} port 33000"))

lines.sort(key=lambda x: x[0])

with open(output, "w", newline="\n") as f:
    for _, line in lines:
        f.write(line + "\n")

print(f"{output} written: {len(lines)} lines")
