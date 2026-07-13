"""Build structured traffic statistics from Zeek logs, plus a prose rendering for LLM context."""

from collections import Counter, defaultdict
from pathlib import Path

from backend.parsing.zeek_logs import load_json_log


def compute_stats(log_dir: Path) -> dict:
    """Aggregate Zeek logs into a structured stats object consumed by the frontend."""
    conn_records = load_json_log(log_dir / "conn.log")
    weird_records = load_json_log(log_dir / "weird.log")
    dns_records = load_json_log(log_dir / "dns.log")
    notice_records = load_json_log(log_dir / "notice.log")

    src_ips = Counter()
    dst_ips = Counter()
    services = Counter()
    ports = Counter()
    port_service_map = defaultdict(Counter)
    port_pair_map = defaultdict(Counter)
    conn_states = Counter()
    first_ts = None
    last_ts = None

    for record in conn_records:
        src = record.get("id.orig_h")
        dst = record.get("id.resp_h")
        service = record.get("service")
        port = record.get("id.resp_p")
        conn_state = record.get("conn_state")
        ts = record.get("ts")

        if src:
            src_ips[src] += 1
        if dst:
            dst_ips[dst] += 1
        if service:
            services[service] += 1
        if port is not None:
            ports[port] += 1
            if service:
                port_service_map[port][service] += 1
            if src and dst:
                port_pair_map[port][f"{src} -> {dst}"] += 1
        if conn_state:
            conn_states[conn_state] += 1
        if isinstance(ts, (int, float)):
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)

    weird_names = Counter(r["name"] for r in weird_records if r.get("name"))
    dns_queries = Counter(r["query"] for r in dns_records if r.get("query"))

    indicators = []
    if ports:
        port, count = ports.most_common(1)[0]
        indicators.append(f"Most targeted destination port: {port} with {count} connections")
    if src_ips:
        ip, count = src_ips.most_common(1)[0]
        indicators.append(f"Most active source IP: {ip} with {count} connections")
    if weird_names:
        name, count = weird_names.most_common(1)[0]
        indicators.append(f"Most common weird event: {name} with {count} occurrences")
    if conn_states:
        state, count = conn_states.most_common(1)[0]
        indicators.append(f"Most common connection state: {state} with {count} occurrences")

    return {
        "total_connections": len(conn_records),
        "total_weird": len(weird_records),
        "total_dns": len(dns_records),
        "total_notices": len(notice_records),
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "capture_start_ts": first_ts,
        "capture_end_ts": last_ts,
        "top_src_ips": [{"ip": ip, "count": c} for ip, c in src_ips.most_common(5)],
        "top_dst_ips": [{"ip": ip, "count": c} for ip, c in dst_ips.most_common(5)],
        "top_services": [{"name": s, "count": c} for s, c in services.most_common(10)],
        "top_ports": [
            {
                "port": port,
                "count": count,
                "service": (
                    port_service_map[port].most_common(1)[0][0]
                    if port_service_map[port]
                    else "unknown"
                ),
                "top_path": (
                    port_pair_map[port].most_common(1)[0][0]
                    if port_pair_map[port]
                    else "unknown"
                ),
            }
            for port, count in ports.most_common(10)
        ],
        "connection_states": [{"state": s, "count": c} for s, c in conn_states.most_common(10)],
        "dns_queries": [{"query": q, "count": c} for q, c in dns_queries.most_common(10)],
        "weird_events": [{"name": n, "count": c} for n, c in weird_names.most_common(10)],
        "indicators": indicators,
    }


def render_evidence(stats: dict) -> str:
    """Render the structured stats as prose used as LLM context."""
    lines = [
        "PCAP forensic summary from Zeek logs",
        "",
        f"Total connections: {stats['total_connections']}",
        f"Total weird events: {stats['total_weird']}",
        f"Total DNS events: {stats['total_dns']}",
        f"Total notice events: {stats['total_notices']}",
        f"Unique source IPs: {stats['unique_src_ips']}",
        f"Unique destination IPs: {stats['unique_dst_ips']}",
    ]

    if stats["capture_start_ts"] and stats["capture_end_ts"]:
        duration = stats["capture_end_ts"] - stats["capture_start_ts"]
        lines.append(f"Capture timespan: {duration:.1f} seconds")

    def section(title: str, items: list[str]):
        lines.append(f"\n{title}:")
        if items:
            lines.extend(f"- {item}" for item in items)
        else:
            lines.append("- None")

    section("Top source IPs", [f"{e['ip']}: {e['count']} connections" for e in stats["top_src_ips"]])
    section("Top destination IPs", [f"{e['ip']}: {e['count']} connections" for e in stats["top_dst_ips"]])
    section("Top services", [f"{e['name']}: {e['count']}" for e in stats["top_services"]])
    section(
        "Top destination ports",
        [
            f"Port {e['port']}: {e['count']} connections | "
            f"Likely service: {e['service']} | Most common path: {e['top_path']}"
            for e in stats["top_ports"]
        ],
    )
    section("Connection states", [f"{e['state']}: {e['count']}" for e in stats["connection_states"]])
    section("Top weird events", [f"{e['name']}: {e['count']}" for e in stats["weird_events"]])
    section("Top DNS queries", [f"{e['query']}: {e['count']}" for e in stats["dns_queries"]])
    section(
        "Potential indicators observed",
        stats["indicators"] or ["No obvious indicators extracted from available Zeek logs"],
    )

    return "\n".join(lines)
