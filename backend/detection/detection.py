"""PacketIQ threat detection over Zeek conn.log / ssh.log.

Detects:
  1. Port scans        — one source touching many ports/hosts in a short window
  2. DDoS              — many sources AND high connection volume against one target
  3. Brute force       — repeated *failed* connections to auth services
  4. SSH brute force   — failed authentication attempts from ssh.log when available

Thresholds are environment-configurable so operators can tune sensitivity
without code changes.
"""

import datetime
import json
import logging
import os
from collections import defaultdict
from pathlib import Path

from backend.parsing.zeek_logs import load_json_log

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


# ─── Thresholds ───────────────────────────────────────────────────────────────

PORT_SCAN_UNIQUE_PORTS = _env_int("DETECT_PORT_SCAN_UNIQUE_PORTS", 15)
PORT_SCAN_UNIQUE_HOSTS = _env_int("DETECT_PORT_SCAN_UNIQUE_HOSTS", 10)
PORT_SCAN_WINDOW_SECS = _env_float("DETECT_PORT_SCAN_WINDOW_SECS", 60.0)

DDOS_MIN_SRC_IPS = _env_int("DETECT_DDOS_MIN_SRC_IPS", 50)
DDOS_MIN_CONNECTIONS = _env_int("DETECT_DDOS_MIN_CONNECTIONS", 200)
DDOS_WINDOW_SECS = _env_float("DETECT_DDOS_WINDOW_SECS", 60.0)

BRUTE_FORCE_MIN_FAILED = _env_int("DETECT_BRUTE_FORCE_MIN_FAILED", 5)
BRUTE_FORCE_HIGH_RATIO = _env_float("DETECT_BRUTE_FORCE_HIGH_RATIO", 0.7)
BRUTE_FORCE_WINDOW_SECS = _env_float("DETECT_BRUTE_FORCE_WINDOW_SECS", 120.0)

# Application-layer brute force: TCP completes (SF) but each attempt only
# exchanges a tiny login/reject payload. Legitimate sessions transfer data.
BRUTE_FORCE_SMALL_BYTES = _env_int("DETECT_BRUTE_FORCE_SMALL_BYTES", 400)
BRUTE_FORCE_MIN_SMALL = _env_int("DETECT_BRUTE_FORCE_MIN_SMALL", 20)
BRUTE_FORCE_SMALL_HIGH = _env_int("DETECT_BRUTE_FORCE_SMALL_HIGH", 100)

# HTTP brute force: repeated auth-rejected responses from http.log.
HTTP_BRUTE_FORCE_MIN_FAILED = _env_int("DETECT_HTTP_BRUTE_FORCE_MIN_FAILED", 10)

# Ports of services that authenticate clients. Covers remote access, file
# transfer, mail, directory, database, and management protocols.
AUTH_PORTS = {
    21,                  # FTP
    22,                  # SSH / SFTP
    23, 2323,            # Telnet
    25, 465, 587,        # SMTP (auth)
    88,                  # Kerberos
    110, 995,            # POP3
    139, 445,            # SMB / NetBIOS
    143, 993,            # IMAP
    389, 636,            # LDAP
    1433,                # MS SQL Server
    1521,                # Oracle
    3306,                # MySQL / MariaDB
    3389,                # RDP
    5060, 5061,          # SIP
    5432,                # PostgreSQL
    5900, 5901, 5902, 5903,  # VNC
    5985, 5986,          # WinRM
    6379,                # Redis
    27017,               # MongoDB
}

# Zeek-identified services that authenticate clients — catches these
# protocols even on non-standard ports (Zeek's service field is derived
# from protocol analysis, not the port number).
AUTH_SERVICES = {
    "ssh", "ftp", "telnet", "rdp", "smtp", "pop3", "imap", "smb",
    "gssapi", "ntlm", "krb", "krb_tcp", "ldap", "ldaps", "mysql",
    "postgresql", "mssql", "mongodb", "redis", "vnc", "sip", "winrm",
}

# Zeek conn_states that indicate the connection did not complete normally.
FAILED_STATES = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR"}


# ─── Record accessors ─────────────────────────────────────────────────────────

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
            dst_ports = {get_dst_port(r) for r in window if get_dst_port(r) > 0}
            dst_hosts = {get_dst(r) for r in window if get_dst(r)}

            if len(dst_ports) >= PORT_SCAN_UNIQUE_PORTS or len(dst_hosts) >= PORT_SCAN_UNIQUE_HOSTS:
                # Severity scales with how far past the threshold the activity goes.
                wide = (
                    len(dst_ports) >= PORT_SCAN_UNIQUE_PORTS * 3
                    or len(dst_hosts) >= PORT_SCAN_UNIQUE_HOSTS * 3
                )
                alerts.append({
                    "type": "port_scan",
                    "severity": "high" if wide else "medium",
                    "src_ip": src_ip,
                    "unique_ports": len(dst_ports),
                    "unique_hosts": len(dst_hosts),
                    "window_secs": PORT_SCAN_WINDOW_SECS,
                    "first_seen_ts": get_ts(conns[window_start]),
                    "last_seen_ts": ts,
                    "sample_ports": sorted(dst_ports)[:20],
                    "evidence": (
                        f"{src_ip} contacted {len(dst_ports)} unique ports "
                        f"and {len(dst_hosts)} unique hosts within {PORT_SCAN_WINDOW_SECS:.0f} seconds."
                    ),
                    "recommendation": (
                        "Verify whether this source is an authorized scanner. If not, "
                        "block it at the perimeter and review what services it reached."
                    ),
                })
                break

    return alerts


# ─── 2. DDoS Detection ────────────────────────────────────────────────────────

def detect_ddos(records: list[dict]) -> list[dict]:
    """Require BOTH many distinct sources and high volume — either alone is
    normal for a busy server and produced false positives."""
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
            src_ips = {get_src(r) for r in window if get_src(r)}

            if len(src_ips) >= DDOS_MIN_SRC_IPS and len(window) >= DDOS_MIN_CONNECTIONS:
                total_bytes = sum(
                    safe_int(r.get("orig_bytes"), 0) + safe_int(r.get("resp_bytes"), 0)
                    for r in window
                )
                failed = sum(1 for r in window if r.get("conn_state") in FAILED_STATES)

                alerts.append({
                    "type": "ddos",
                    "severity": "high",
                    "dst_ip": dst_ip,
                    "unique_src_ips": len(src_ips),
                    "total_connections": len(window),
                    "failed_connections": failed,
                    "total_bytes": total_bytes,
                    "window_secs": DDOS_WINDOW_SECS,
                    "first_seen_ts": get_ts(conns[window_start]),
                    "last_seen_ts": ts,
                    "evidence": (
                        f"{dst_ip} received {len(window)} connections from "
                        f"{len(src_ips)} unique source IPs within {DDOS_WINDOW_SECS:.0f} seconds "
                        f"({failed} incomplete/failed)."
                    ),
                    "recommendation": (
                        "Confirm service degradation on the target, enable rate limiting "
                        "or upstream DDoS mitigation, and capture source IP ranges for blocking."
                    ),
                })
                break

    return alerts


# ─── 3. Brute Force Detection from conn.log ───────────────────────────────────

def _conn_bytes(record: dict) -> int:
    return safe_int(record.get("orig_bytes"), 0) + safe_int(record.get("resp_bytes"), 0)


def get_services(record: dict) -> set[str]:
    """Zeek's service field; may hold multiple comma-separated identifications."""
    service = record.get("service")
    if not service:
        return set()
    return {s.strip().lower() for s in str(service).split(",") if s.strip()}


def is_auth_target(record: dict) -> bool:
    """True if the connection targets an authenticating service, identified
    by well-known port OR by Zeek's protocol analysis (non-standard ports)."""
    if get_dst_port(record) in AUTH_PORTS:
        return True
    return bool(get_services(record) & AUTH_SERVICES)


def detect_brute_force(records: list[dict]) -> list[dict]:
    """Detect brute force against auth services via two signals:

    1. Repeated FAILED connections (rejected / no reply / reset).
    2. Repeated COMPLETED-but-tiny connections: protocols like FTP and SSH
       accept the TCP connection and reject the login at the application
       layer, so each attempt completes (SF) after exchanging only a small
       login/reject payload. Legitimate sessions transfer real data.

    A batch job making 50 successful SFTP transfers matches neither signal.
    """
    alerts = []
    by_target = defaultdict(list)

    for record in records:
        src = get_src(record)
        dst = get_dst(record)
        port = get_dst_port(record)

        if src and dst and port and is_auth_target(record):
            by_target[(src, dst, port)].append(record)

    for (src_ip, dst_ip, dst_port), conns in by_target.items():
        total_attempts = len(conns)
        services = set().union(*(get_services(r) for r in conns)) & AUTH_SERVICES
        service_label = ", ".join(sorted(services)) if services else f"port {dst_port}"
        failed = [r for r in conns if r.get("conn_state") in FAILED_STATES]
        small_completed = [
            r for r in conns
            if r.get("conn_state") not in FAILED_STATES
            and _conn_bytes(r) < BRUTE_FORCE_SMALL_BYTES
        ]

        timestamps = sorted(get_ts(r) for r in conns)
        alert = None

        if len(failed) >= BRUTE_FORCE_MIN_FAILED:
            failed_ratio = len(failed) / total_attempts
            alert = {
                "severity": "high" if failed_ratio >= BRUTE_FORCE_HIGH_RATIO else "medium",
                "failed_attempts": len(failed),
                "failed_ratio": round(failed_ratio, 2),
                "reason": (
                    f"{len(failed)} of {total_attempts} connections to {service_label} "
                    f"failed ({failed_ratio:.0%})"
                ),
                "evidence": (
                    f"{src_ip} made {total_attempts} connections to {dst_ip}:{dst_port} "
                    f"({service_label}); {len(failed)} showed failed/incomplete states."
                ),
            }

        elif len(small_completed) >= BRUTE_FORCE_MIN_SMALL:
            avg_bytes = sum(_conn_bytes(r) for r in small_completed) // len(small_completed)
            alert = {
                "severity": "high" if len(small_completed) >= BRUTE_FORCE_SMALL_HIGH else "medium",
                "failed_attempts": len(small_completed),
                "avg_bytes_per_attempt": avg_bytes,
                "reason": (
                    f"{len(small_completed)} completed connections to {service_label} "
                    f"averaging only {avg_bytes} bytes each — consistent with "
                    f"repeated application-layer login failures"
                ),
                "evidence": (
                    f"{src_ip} made {total_attempts} connections to {dst_ip}:{dst_port} "
                    f"({service_label}), {len(small_completed)} of which completed but "
                    f"exchanged under {BRUTE_FORCE_SMALL_BYTES} bytes — too small for "
                    f"legitimate sessions."
                ),
            }

        if alert is None:
            continue

        alert.update({
            "type": "brute_force",
            "service": service_label,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "total_attempts": total_attempts,
            "first_seen_ts": timestamps[0],
            "last_seen_ts": timestamps[-1],
            "recommendation": (
                "Review authentication logs on the target, block or rate-limit the "
                "source IP, and enforce key-based or MFA authentication."
            ),
        })
        alerts.append(alert)

    return alerts


# ─── HTTP Brute Force Detection from http.log ─────────────────────────────────

def detect_http_brute_force(http_records: list[dict]) -> list[dict]:
    """Repeated authentication-rejected HTTP responses (401/403/407) from one
    source to one target — login form or basic-auth brute force."""
    alerts = []
    by_target = defaultdict(list)

    for record in http_records:
        src = get_src(record)
        dst = get_dst(record)
        status = safe_int(record.get("status_code"), 0)

        if src and dst and status in (401, 403, 407):
            by_target[(src, dst)].append(record)

    for (src_ip, dst_ip), failures in by_target.items():
        if len(failures) < HTTP_BRUTE_FORCE_MIN_FAILED:
            continue

        timestamps = sorted(get_ts(r) for r in failures)
        top_uri = max(
            ((uri, sum(1 for f in failures if f.get("uri") == uri))
             for uri in {f.get("uri") for f in failures}),
            key=lambda x: x[1],
        )[0]
        host = failures[-1].get("host") or str(dst_ip)
        dst_port = get_dst_port(failures[-1]) or 80

        alerts.append({
            "type": "brute_force",
            "subtype": "http",
            "service": "http",
            "severity": "high" if len(failures) >= HTTP_BRUTE_FORCE_MIN_FAILED * 5 else "medium",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "failed_attempts": len(failures),
            "total_attempts": len(failures),
            "target_uri": top_uri,
            "first_seen_ts": timestamps[0],
            "last_seen_ts": timestamps[-1],
            "reason": (
                f"{len(failures)} HTTP auth-rejected responses (401/403/407) "
                f"from {host}, most targeting {top_uri}"
            ),
            "evidence": (
                f"{src_ip} received {len(failures)} authentication-rejected HTTP "
                f"responses from {host} ({dst_ip}), most frequently for {top_uri}."
            ),
            "recommendation": (
                "Review web server auth logs, enable account lockout / CAPTCHA / "
                "rate limiting on the login endpoint, and block the source IP."
            ),
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
            failed = [r for r in window if r.get("auth_success") is False]
            total_auth_attempts = sum(safe_int(r.get("auth_attempts"), 1) for r in failed)

            if len(failed) >= BRUTE_FORCE_MIN_FAILED or total_auth_attempts >= BRUTE_FORCE_MIN_FAILED:
                ssh_client = failed[-1].get("client", "unknown") if failed else "unknown"

                alerts.append({
                    "type": "brute_force",
                    "subtype": "ssh",
                    "severity": "high",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": 22,
                    "failed_attempts": len(failed),
                    "total_attempts": len(window),
                    "total_auth_attempts": total_auth_attempts,
                    "window_secs": BRUTE_FORCE_WINDOW_SECS,
                    "first_seen_ts": get_ts(conns[window_start]),
                    "last_seen_ts": ts,
                    "ssh_client": ssh_client,
                    "reason": "SSH authentication failures from ssh.log",
                    "evidence": (
                        f"{src_ip} made {len(failed)} failed SSH connections with "
                        f"{total_auth_attempts} total auth attempts against {dst_ip}:22."
                    ),
                    "recommendation": (
                        "Review SSH auth logs, block or rate-limit the source IP, "
                        "disable password authentication, and require key-based authentication."
                    ),
                })
                break

    return alerts


# ─── Deduplication ────────────────────────────────────────────────────────────

def dedupe_brute_force(alerts: list[dict]) -> list[dict]:
    """Prefer ssh.log-based alerts over conn.log-based ones for the same
    src/dst pair — they carry real authentication evidence."""
    ssh_pairs = {
        (a["src_ip"], a["dst_ip"])
        for a in alerts
        if a.get("subtype") == "ssh"
    }
    return [
        a for a in alerts
        if a.get("subtype") == "ssh"
        or (a["src_ip"], a["dst_ip"]) not in ssh_pairs
        or a["dst_port"] != 22
    ]


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def run_detections(
    conn_log_path: str,
    output_path: str | None = None,
    ssh_log_path: str | None = None,
) -> dict:
    records = load_json_log(conn_log_path)
    logger.info("Running detections on %d connection records", len(records))

    port_scan_alerts = detect_port_scans(records)
    ddos_alerts = detect_ddos(records)
    brute_force_alerts = detect_brute_force(records)

    log_dir = Path(conn_log_path).parent

    if ssh_log_path is None:
        candidate = log_dir / "ssh.log"
        if candidate.exists():
            ssh_log_path = str(candidate)

    if ssh_log_path and Path(ssh_log_path).exists():
        ssh_records = load_json_log(ssh_log_path)
        brute_force_alerts.extend(detect_ssh_brute_force(ssh_records))

    http_log = log_dir / "http.log"
    if http_log.exists():
        brute_force_alerts.extend(detect_http_brute_force(load_json_log(http_log)))

    brute_force_alerts = dedupe_brute_force(brute_force_alerts)

    results = {
        "port_scans": port_scan_alerts,
        "ddos": ddos_alerts,
        "brute_force": brute_force_alerts,
    }

    logger.info(
        "Detections complete: %d port scans, %d ddos, %d brute force",
        len(port_scan_alerts), len(ddos_alerts), len(brute_force_alerts),
    )

    if output_path:
        save_to_json(results, output_path)

    return results


def save_to_json(results: dict, output_path: str) -> None:
    payload = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {
            "port_scans": len(results["port_scans"]),
            "ddos": len(results["ddos"]),
            "brute_force": len(results["brute_force"]),
            "total": sum(len(v) for v in results.values()),
        },
        "detections": results,
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    conn_path = sys.argv[1] if len(sys.argv) > 1 else "conn.log"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "detection.json"
    results = run_detections(conn_path, out_path)
    print(json.dumps(results, indent=2))
