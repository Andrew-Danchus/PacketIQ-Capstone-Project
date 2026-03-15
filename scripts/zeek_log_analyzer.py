import json
from collections import Counter
from pathlib import Path

# Folder that contains Zeek logs (relative to this script)
LOG_DIR = Path("logs")

# Log file paths (inside LOG_DIR)
CONN_LOG = LOG_DIR / "conn.log"
WEIRD_LOG = LOG_DIR / "weird.log"
PACKET_FILTER_LOG = LOG_DIR / "packet_filter.log"


def analyze_conn_log(file_path: Path):
    if not file_path.exists():
        print(f"[!] Missing: {file_path}")
        return

    total_connections = 0
    src_ips = Counter()
    dst_ips = Counter()
    services = Counter()

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            total_connections += 1
            src = record.get("id.orig_h")
            dst = record.get("id.resp_h")
            service = record.get("service")

            if src:
                src_ips[src] += 1
            if dst:
                dst_ips[dst] += 1
            if service:
                services[service] += 1

    print("\n---- Connection Summary ----")
    print("Total Connections:", total_connections)

    print("\nTop Source IPs:")
    for ip, count in src_ips.most_common(10):
        print(ip, count)

    print("\nTop Destination IPs:")
    for ip, count in dst_ips.most_common(10):
        print(ip, count)

    print("\nServices Observed:")
    for svc, count in services.most_common():
        print(svc, count)


def analyze_weird_log(file_path: Path):
    if not file_path.exists():
        print(f"[!] Missing: {file_path}")
        return

    weird_events = Counter()

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            weird = record.get("name")
            if weird:
                weird_events[weird] += 1

    print("\n---- Weird Events ----")
    for event, count in weird_events.most_common():
        print(event, count)


def analyze_packet_filter_log(file_path: Path):
    if not file_path.exists():
        print(f"[!] Missing: {file_path}")
        return

    filters = Counter()

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            node = record.get("node")
            if node:
                filters[node] += 1

    print("\n---- Packet Filter Summary ----")
    for node, count in filters.most_common():
        print(node, count)


def main():
    analyze_conn_log(CONN_LOG)
    analyze_weird_log(WEIRD_LOG)
    analyze_packet_filter_log(PACKET_FILTER_LOG)


if __name__ == "__main__":
    main()