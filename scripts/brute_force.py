import json
from collections import defaultdict
from pathlib import Path

LOG_FILE = Path("logs/conn.log")

ATTEMPT_THRESHOLD = 20   # login attempts
TIME_WINDOW = 60         # seconds

AUTH_PORTS = {21, 22, 3389}   # FTP, SSH, RDP

connections = defaultdict(list)

# Read conn.log
with LOG_FILE.open("r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()

        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        ts = float(record.get("ts", 0))
        src = record.get("id.orig_h")
        dst = record.get("id.resp_h")
        port = record.get("id.resp_p")

        if not src or not dst or port not in AUTH_PORTS:
            continue

        connections[(src, dst, port)].append(ts)

print("\nPotential Brute Force Attempts:\n")

for (src, dst, port), times in connections.items():

    times.sort()

    for i in range(len(times)):
        start = times[i]
        count = 1

        for j in range(i + 1, len(times)):
            if times[j] - start <= TIME_WINDOW:
                count += 1
            else:
                break

        if count >= ATTEMPT_THRESHOLD:
            print(f"Attacker : {src}")
            print(f"Target   : {dst}")
            print(f"Service  : Port {port}")
            print(f"Attempts : {count} in {TIME_WINDOW} seconds")
            print("-" * 40)
            break