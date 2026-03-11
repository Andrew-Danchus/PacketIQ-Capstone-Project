"""
Analyzes Zeek JSON logs to detect:
  1. Port Scans
  2. DDoS Attacks
  3. Brute Force Attacks
"""

import json
import datetime
from collections import defaultdict

# ─── Thresholds ───────────────────────────────────────────────────────────────
PORT_SCAN_UNIQUE_PORTS   = 15    # distinct dst ports from one src in the window
PORT_SCAN_UNIQUE_HOSTS   = 10    # distinct dst hosts from one src in the window
PORT_SCAN_WINDOW_SECS    = 60.0

DDOS_MIN_SRC_IPS         = 50    # distinct source IPs hammering one target
DDOS_MIN_CONNECTIONS     = 200   # total connections to one target
DDOS_WINDOW_SECS         = 60.0

BRUTE_FORCE_MIN_ATTEMPTS = 10    # failed attempts from one src to same dst:port
BRUTE_FORCE_PORTS        = {22, 21, 23, 25, 110, 143, 3389, 5900}  # SSH/FTP/Telnet/RDP/VNC/Mail
BRUTE_FORCE_WINDOW_SECS  = 120.0

# Zeek conn_state values that indicate a rejected / failed connection
FAILED_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}


#  Log Loader

def load_conn_log(path: str) -> list[dict]:
    """Read a Zeek conn.log (JSON format) and return a list of record dicts."""
    records = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


#  1. Port Scan Detection 

def detect_port_scans(records: list[dict]) -> list[dict]:
    """
    Flag source IPs that contact an unusual number of distinct destination
    ports or destination hosts within a rolling time window.

    Returns a list of alert dicts, one per offending source IP.
    """
    alerts = []

    # Group all records by source IP
    by_src: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        src = r.get("id.orig_h") or r.get("orig_h")
        if src:
            by_src[src].append(r)

    for src_ip, conns in by_src.items():
        # Sort by timestamp so we can slide a time window
        conns.sort(key=lambda r: float(r.get("ts", 0)))

        window_start = 0
        for i, conn in enumerate(conns):
            ts = float(conn.get("ts", 0))

            # Advance window start to keep within the window
            while float(conns[window_start].get("ts", 0)) < ts - PORT_SCAN_WINDOW_SECS:
                window_start += 1

            window = conns[window_start : i + 1]
            dst_ports = {int(r.get("id.resp_p") or r.get("resp_p", 0)) for r in window}
            dst_hosts = {r.get("id.resp_h") or r.get("resp_h") for r in window}

            if (len(dst_ports) >= PORT_SCAN_UNIQUE_PORTS or
                    len(dst_hosts) >= PORT_SCAN_UNIQUE_HOSTS):
                alerts.append({
                    "type":          "port_scan",
                    "src_ip":        src_ip,
                    "unique_ports":  len(dst_ports),
                    "unique_hosts":  len(dst_hosts),
                    "window_secs":   PORT_SCAN_WINDOW_SECS,
                    "first_seen_ts": float(conns[window_start].get("ts", 0)),
                    "last_seen_ts":  ts,
                    "sample_ports":  sorted(dst_ports)[:20],
                })
                break  # one alert per source IP is enough

    return alerts


#  2. DDoS Detection

def detect_ddos(records: list[dict]) -> list[dict]:
    """
    Flag destination IPs that receive connections from an unusually large
    number of distinct source IPs within a rolling time window (volumetric DDoS).

    Returns a list of alert dicts, one per targeted destination IP.
    """
    alerts = []

    # Group all records by destination IP
    by_dst: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        dst = r.get("id.resp_h") or r.get("resp_h")
        if dst:
            by_dst[dst].append(r)

    for dst_ip, conns in by_dst.items():
        conns.sort(key=lambda r: float(r.get("ts", 0)))

        window_start = 0
        for i, conn in enumerate(conns):
            ts = float(conn.get("ts", 0))

            while float(conns[window_start].get("ts", 0)) < ts - DDOS_WINDOW_SECS:
                window_start += 1

            window = conns[window_start : i + 1]
            src_ips = {r.get("id.orig_h") or r.get("orig_h") for r in window}

            if (len(src_ips) >= DDOS_MIN_SRC_IPS or
                    len(window) >= DDOS_MIN_CONNECTIONS):
                total_bytes = sum(
                    int(r.get("orig_bytes") or 0) + int(r.get("resp_bytes") or 0)
                    for r in window
                )
                alerts.append({
                    "type":             "ddos",
                    "dst_ip":           dst_ip,
                    "unique_src_ips":   len(src_ips),
                    "total_connections": len(window),
                    "total_bytes":      total_bytes,
                    "window_secs":      DDOS_WINDOW_SECS,
                    "first_seen_ts":    float(conns[window_start].get("ts", 0)),
                    "last_seen_ts":     ts,
                })
                break  # one alert per target IP

    return alerts


#  3. Brute Force Detection

def detect_brute_force(records: list[dict]) -> list[dict]:
    """
    Flag source IPs that make many failed connection attempts to the same
    destination IP and port (e.g., SSH, RDP, FTP) in a rolling time window.

    Returns a list of alert dicts, one per (src_ip, dst_ip, dst_port) triple.
    """
    alerts = []

    # Group by (src_ip, dst_ip, dst_port) — only care about auth-related ports
    by_target: dict[tuple, list[dict]] = defaultdict(list)
    for r in records:
        src  = r.get("id.orig_h") or r.get("orig_h")
        dst  = r.get("id.resp_h") or r.get("resp_h")
        port = int(r.get("id.resp_p") or r.get("resp_p", 0))
        if src and dst and port in BRUTE_FORCE_PORTS:
            by_target[(src, dst, port)].append(r)

    for (src_ip, dst_ip, dst_port), conns in by_target.items():
        conns.sort(key=lambda r: float(r.get("ts", 0)))

        window_start = 0
        for i, conn in enumerate(conns):
            ts = float(conn.get("ts", 0))

            while float(conns[window_start].get("ts", 0)) < ts - BRUTE_FORCE_WINDOW_SECS:
                window_start += 1

            window = conns[window_start : i + 1]
            failed = [r for r in window if r.get("conn_state") in FAILED_STATES]

            if len(failed) >= BRUTE_FORCE_MIN_ATTEMPTS:
                alerts.append({
                    "type":            "brute_force",
                    "src_ip":          src_ip,
                    "dst_ip":          dst_ip,
                    "dst_port":        dst_port,
                    "failed_attempts": len(failed),
                    "total_attempts":  len(window),
                    "window_secs":     BRUTE_FORCE_WINDOW_SECS,
                    "first_seen_ts":   float(conns[window_start].get("ts", 0)),
                    "last_seen_ts":    ts,
                })
                break  # one alert per (src, dst, port) triple

    return alerts


#  Main Entry Point 

def run_detections(conn_log_path: str = "conn.log",
                   output_path: str = "detection.json") -> dict:
    """
    Load Zeek conn.log and run all three detectors in order:
      1. Port Scan
      2. DDoS
      3. Brute Force

    Saves results to `output_path` as JSON and returns the results dict.
    """
    records = load_conn_log(conn_log_path)

    port_scan_alerts   = detect_port_scans(records)
    ddos_alerts        = detect_ddos(records)
    brute_force_alerts = detect_brute_force(records)

    results = {
        "port_scans":  port_scan_alerts,
        "ddos":        ddos_alerts,
        "brute_force": brute_force_alerts,
    }

    _print_summary(results)
    save_to_json(results, output_path)
    return results


def save_to_json(results: dict, output_path: str = "detection.json") -> None:
    """Serialize all detection results to a JSON file."""
    payload = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {
            "port_scans":  len(results["port_scans"]),
            "ddos":        len(results["ddos"]),
            "brute_force": len(results["brute_force"]),
        },
        "detections": results,
    }
    with open(output_path, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"Detection results saved -> {output_path}")


def _print_summary(results: dict) -> None:
    print("\n" + "=" * 50)
    print("  PacketIQ Detection Report")
    print("=" * 50)

    # Port Scans
    print(f"\n[1] Port Scan Detections: {len(results['port_scans'])}")
    for a in results["port_scans"]:
        print(f"    {a['src_ip']} → {a['unique_ports']} ports / "
              f"{a['unique_hosts']} hosts in {a['window_secs']}s")

    # DDoS
    print(f"\n[2] DDoS Detections: {len(results['ddos'])}")
    for a in results["ddos"]:
        print(f"    Target: {a['dst_ip']} <- {a['unique_src_ips']} IPs, "
              f"{a['total_connections']} conns, {a['total_bytes']} bytes "
              f"in {a['window_secs']}s")

    # Brute Force
    print(f"\n[3] Brute Force Detections: {len(results['brute_force'])}")
    for a in results["brute_force"]:
        print(f"    {a['src_ip']} → {a['dst_ip']}:{a['dst_port']} — "
              f"{a['failed_attempts']} failed / {a['total_attempts']} total "
              f"in {a['window_secs']}s")

    print()


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "conn.log"
    out  = sys.argv[2] if len(sys.argv) > 2 else "detection.json"
    run_detections(path, out)
