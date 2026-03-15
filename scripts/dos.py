import json
from collections import defaultdict
from pathlib import Path

LOG_FILE = Path("logs/conn.log")

DOS_THRESHOLD = 200   # connections
TIME_WINDOW = 10      # seconds

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

        if not src or not dst:
            continue

        connections[(src, dst)].append(ts)

print("\nPotential DoS Activity:\n")

for (src, dst), times in connections.items():

    times.sort()

    for i in range(len(times)):
        start = times[i]
        count = 1

        for j in range(i + 1, len(times)):
            if times[j] - start <= TIME_WINDOW:
                count += 1
            else:
                break

        if count >= DOS_THRESHOLD:
            print(f"Attacker: {src}")
            print(f"Target  : {dst}")
            print(f"Connections: {count} in {TIME_WINDOW} seconds")
            print("-" * 40)
            break