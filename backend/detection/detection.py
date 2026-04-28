"""
PacketIQ detection.py

Analyzes Zeek JSON logs to detect:
  1. Port scans
  2. DDoS / high-volume traffic
  3. Brute force attempts
  4. SSH brute force from ssh.log when available

This version is less strict for SSH brute force because many SSH login attempts
show as conn_state="SF" in conn.log, meaning the TCP connection succeeded even
though authentication may have failed.
"""

import json
import datetime
from collections import defaultdict
from pathlib import Path


# ─── Thresholds ───────────────────────────────────────────────────────────────

PORT_SCAN_UNIQUE_PORTS = 15
PORT_SCAN_UNIQUE_HOSTS = 10
PORT_SCAN_WINDOW_SECS = 60.0

DDOS_MIN_SRC_IPS = 50
DDOS_MIN_CONNECTIONS = 200
DDOS_WINDOW_SECS = 60.0

BRUTE_FORCE_MIN_ATTEMPTS = 5
BRUTE_FORCE_PORTS = {22, 21, 23, 2323, 25, 110, 143, 3389, 5900}
BRUTE_FORCE_WINDOW_SECS = 120.0

FAILED_STATES = {
    "S0",
    "REJ",
    "RSTO",
    "RSTR",
    "RSTOS0",
    "RSTRH",
    "SH",
    "SHR",
    "OTH",
}


# ─── Log Loaders ──────────────────────────────────────────────────────────────

def load_json_log(path: str) -> list[dict]:
    records = []

    if not path or not Path(path).exists():
        print(f"WARNING: log file not found: {path}")
        return records

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records


def safe_int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def get_src(record: dict):
    return record.get("id.orig_h") or record.get("orig_h")


def get_dst(record: dict):
    return record.get("id.resp_h") or record.get("resp_h")


def get_dst_port(record: dict) -> int:
    return safe_int(record.get("id.resp_p") or record.get("resp_p"), 0)


def get_ts(record: dict) -> float:
    return safe_float(record.get("ts"), 0.0)


# ─── 1. Port Scan Detection ───────────────────────────────────────────────────

def detect_port_scans(records: list[dict]) -> list[dict]:
    alerts = []
    by_src = defaultdict(list)

    for record in records:
        src = get_src(record)
        if src:
            by_src[src].append(record)

    for src_ip, conns in by_src.items():
        conns.sort(key=get_ts)
        window_start = 0

        for i, conn in enumerate(conns):
            ts = get_ts(conn)

            while window_start < i and get_ts(conns[window_start]) < ts - PORT_SCAN_WINDOW_SECS:
                window_start += 1

            window = conns[window_start:i + 1]

            dst_ports = {
                get_dst_port(r)
                for r in window
                if get_dst_port(r) > 0
            }

            dst_hosts = {
                get_dst(r)
                for r in window
                if get_dst(r)
            }

            if len(dst_ports) >= PORT_SCAN_UNIQUE_PORTS or len(dst_hosts) >= PORT_SCAN_UNIQUE_HOSTS:
                alerts.append({
                    "type": "port_scan",
                    "severity": "medium",
                    "src_ip": src_ip,
                    "unique_ports": len(dst_ports),
                    "unique_hosts": len(dst_hosts),
                    "window_secs": PORT_SCAN_WINDOW_SECS,
                    "first_seen_ts": get_ts(conns[window_start]),
                    "last_seen_ts": ts,
                    "sample_ports": sorted(dst_ports)[:20],
                    "evidence": (
                        f"{src_ip} contacted {len(dst_ports)} unique ports "
                        f"and {len(dst_hosts)} unique hosts within {PORT_SCAN_WINDOW_SECS} seconds."
                    ),
                })
                break

    return alerts


# ─── 2. DDoS Detection ────────────────────────────────────────────────────────

def detect_ddos(records: list[dict]) -> list[dict]:
    alerts = []
    by_dst = defaultdict(list)

    for record in records:
        dst = get_dst(record)
        if dst:
            by_dst[dst].append(record)

    for dst_ip, conns in by_dst.items():
        conns.sort(key=get_ts)
        window_start = 0

        for i, conn in enumerate(conns):
            ts = get_ts(conn)

            while window_start < i and get_ts(conns[window_start]) < ts - DDOS_WINDOW_SECS:
                window_start += 1

            window = conns[window_start:i + 1]

            src_ips = {
                get_src(r)
                for r in window
                if get_src(r)
            }

            if len(src_ips) >= DDOS_MIN_SRC_IPS or len(window) >= DDOS_MIN_CONNECTIONS:
                total_bytes = sum(
                    safe_int(r.get("orig_bytes"), 0) + safe_int(r.get("resp_bytes"), 0)
                    for r in window
                )

                alerts.append({
                    "type": "ddos",
                    "severity": "high",
                    "dst_ip": dst_ip,
                    "unique_src_ips": len(src_ips),
                    "total_connections": len(window),
                    "total_bytes": total_bytes,
                    "window_secs": DDOS_WINDOW_SECS,
                    "first_seen_ts": get_ts(conns[window_start]),
                    "last_seen_ts": ts,
                    "evidence": (
                        f"{dst_ip} received {len(window)} connections from "
                        f"{len(src_ips)} unique source IPs within {DDOS_WINDOW_SECS} seconds."
                    ),
                })
                break

    return alerts


# ─── 3. Brute Force Detection from conn.log ───────────────────────────────────

def detect_brute_force(records: list[dict]) -> list[dict]:
    alerts = []
    by_target = defaultdict(list)

    for record in records:
        src = get_src(record)
        dst = get_dst(record)
        port = get_dst_port(record)

        if src and dst and port in BRUTE_FORCE_PORTS:
            by_target[(src, dst, port)].append(record)

    for (src_ip, dst_ip, dst_port), conns in by_target.items():
        total_attempts = len(conns)

        failed = [
            r for r in conns
            if r.get("conn_state") in FAILED_STATES
        ]

        # KEY CHANGE:
        # No time window — detect total behavior
        if total_attempts >= 10:
            alerts.append({
                "type": "brute_force",
                "severity": "high",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "failed_attempts": len(failed),
                "total_attempts": total_attempts,
                "reason": "High number of repeated connections (likely brute force)",
                "evidence": (
                    f"{src_ip} made {total_attempts} connections to "
                    f"{dst_ip}:{dst_port}. {len(failed)} showed failed states."
                ),
                "recommendation": "Block source IP or enable rate limiting."
            })

    return alerts


# ─── 4. SSH Brute Force Detection from ssh.log ────────────────────────────────

def detect_ssh_brute_force(ssh_records: list[dict]) -> list[dict]:
    alerts = []
    by_target = defaultdict(list)

    for record in ssh_records:
        src = get_src(record)
        dst = get_dst(record)

        if src and dst:
            by_target[(src, dst)].append(record)

    for (src_ip, dst_ip), conns in by_target.items():
        conns.sort(key=get_ts)
        window_start = 0

        for i, conn in enumerate(conns):
            ts = get_ts(conn)

            while window_start < i and get_ts(conns[window_start]) < ts - BRUTE_FORCE_WINDOW_SECS:
                window_start += 1

            window = conns[window_start:i + 1]

            failed = [
                r for r in window
                if r.get("auth_success") is False
            ]

            total_auth_attempts = sum(
                safe_int(r.get("auth_attempts"), 1)
                for r in failed
            )

            if len(failed) >= BRUTE_FORCE_MIN_ATTEMPTS or total_auth_attempts >= BRUTE_FORCE_MIN_ATTEMPTS:
                ssh_client = failed[-1].get("client", "unknown") if failed else "unknown"

                alerts.append({
                    "type": "brute_force",
                    "subtype": "ssh",
                    "severity": "high",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": 22,
                    "failed_connections": len(failed),
                    "failed_attempts": len(failed),
                    "total_attempts": len(window),
                    "total_auth_attempts": total_auth_attempts,
                    "window_secs": BRUTE_FORCE_WINDOW_SECS,
                    "first_seen_ts": get_ts(conns[window_start]),
                    "last_seen_ts": ts,
                    "ssh_client": ssh_client,
                    "reason": "SSH authentication failures from ssh.log",
                    "evidence": (
                        f"{src_ip} made {len(failed)} failed SSH connections "
                        f"with {total_auth_attempts} total auth attempts against {dst_ip}:22."
                    ),
                    "recommendation": (
                        "Review SSH auth logs, block or rate-limit the source IP, "
                        "disable password authentication, and require key-based authentication."
                    ),
                })
                break

    return alerts


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def run_detections(
    conn_log_path: str = "conn.log",
    output_path: str = "detection.json",
    ssh_log_path: str | None = None
) -> dict:
    print("\nRunning PacketIQ detections...")
    print(f"DEBUG: conn_log_path = {conn_log_path}")

    records = load_json_log(conn_log_path)

    print(f"DEBUG: conn records loaded: {len(records)}")
    if records:
        print(f"DEBUG: first conn record: {records[0]}")

    port_scan_alerts = detect_port_scans(records)
    ddos_alerts = detect_ddos(records)
    brute_force_alerts = detect_brute_force(records)

    if ssh_log_path is None:
        candidate = Path(conn_log_path).parent / "ssh.log"
        if candidate.exists():
            ssh_log_path = str(candidate)

    print(f"DEBUG: ssh_log_path = {ssh_log_path}")

    if ssh_log_path and Path(ssh_log_path).exists():
        ssh_records = load_json_log(ssh_log_path)

        print(f"DEBUG: ssh records loaded: {len(ssh_records)}")
        if ssh_records:
            print(f"DEBUG: first ssh record: {ssh_records[0]}")

        ssh_alerts = detect_ssh_brute_force(ssh_records)
        brute_force_alerts.extend(ssh_alerts)

        print(f"DEBUG: SSH brute force alerts: {len(ssh_alerts)}")
    else:
        print("DEBUG: ssh.log not found. Using conn.log brute force detection only.")

    results = {
        "port_scans": port_scan_alerts,
        "ddos": ddos_alerts,
        "brute_force": brute_force_alerts,
    }

    _print_summary(results)
    save_to_json(results, output_path)
    print("DEBUG: total conn records:", len(records))

    ports = [get_dst_port(r) for r in records]
    print("DEBUG: port 22 count:", ports.count(22))
    return results


def save_to_json(results: dict, output_path: str = "detection.json") -> None:
    payload = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {
            "port_scans": len(results["port_scans"]),
            "ddos": len(results["ddos"]),
            "brute_force": len(results["brute_force"]),
            "total": (
                len(results["port_scans"])
                + len(results["ddos"])
                + len(results["brute_force"])
            ),
        },
        "detections": results,
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    print(f"Detection results saved -> {output_path}")


def _print_summary(results: dict) -> None:
    print("\n" + "=" * 50)
    print("  PacketIQ Detection Report")
    print("=" * 50)

    print(f"\n[1] Port Scan Detections: {len(results['port_scans'])}")
    for alert in results["port_scans"]:
        print(
            f"    {alert['src_ip']} -> "
            f"{alert['unique_ports']} ports / "
            f"{alert['unique_hosts']} hosts in "
            f"{alert['window_secs']}s"
        )

    print(f"\n[2] DDoS Detections: {len(results['ddos'])}")
    for alert in results["ddos"]:
        print(
            f"    Target {alert['dst_ip']} <- "
            f"{alert['unique_src_ips']} IPs, "
            f"{alert['total_connections']} connections, "
            f"{alert['total_bytes']} bytes in "
            f"{alert['window_secs']}s"
        )

    print(f"\n[3] Brute Force Detections: {len(results['brute_force'])}")
    for alert in results["brute_force"]:
        window = alert.get("window_secs", "N/A")
        print(
            f"    {alert['src_ip']} -> {alert['dst_ip']}:{alert['dst_port']} — "
            f"{alert['failed_attempts']} failed / "
            f"{alert['total_attempts']} total"
            + (f" in {window}s" if window != "N/A" else "")
        )

        if alert.get("subtype") == "ssh":
            print(
                f"      SSH auth attempts: {alert.get('total_auth_attempts', 0)}, "
                f"client: {alert.get('ssh_client', 'unknown')}"
            )

        print(f"      Reason: {alert.get('reason', 'N/A')}")

    print()


if __name__ == "__main__":
    import sys

    conn_path = sys.argv[1] if len(sys.argv) > 1 else "conn.log"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "detection.json"

    run_detections(conn_path, out_path)