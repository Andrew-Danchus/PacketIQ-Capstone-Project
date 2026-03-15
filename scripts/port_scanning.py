import json
from collections import defaultdict
from pathlib import Path

LOG_FILE = Path("logs/conn.log")

PORT_SCAN_THRESHOLD = 20   # number of ports
TIME_WINDOW = 60           # seconds

connections = defaultdict(list)

# Read Zeek conn.log
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

        if not src or not dst or not port:
            continue

        connections[(src, dst)].append((ts, port))

print("\nPotential Port Scans:\n")

for (src, dst), events in connections.items():

    events.sort()

    for i in range(len(events)):
        start_time = events[i][0]
        ports = set()

        for j in range(i, len(events)):
            ts, port = events[j]

            if ts - start_time <= TIME_WINDOW:
                ports.add(port)
            else:
                break

        if len(ports) >= PORT_SCAN_THRESHOLD:
            print(f"Scanner: {src}")
            print(f"Target : {dst}")
            print(f"Ports  : {len(ports)} scanned in {TIME_WINDOW} seconds")
            print("-" * 40)
            break