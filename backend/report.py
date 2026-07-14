"""Generate a shareable markdown report for a completed analysis job."""

import datetime
import logging

from backend.db import jobs
from backend.ollama.service import analyze_evidence
from backend.rag.pipeline import query_rag_context

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _fmt_ts(ts) -> str:
    if ts is None:
        return "unknown"
    try:
        return datetime.datetime.fromtimestamp(float(ts), tz=datetime.timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return str(ts)


def _detection_lines(detections: dict) -> list[str]:
    alerts = (
        detections.get("port_scans", [])
        + detections.get("ddos", [])
        + detections.get("brute_force", [])
    )
    if not alerts:
        return ["_No port scans, DDoS patterns, or brute-force attempts were detected._"]

    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.get("severity"), 3))
    label = {"port_scan": "Port Scan", "ddos": "DDoS", "brute_force": "Brute Force"}

    lines = []
    for a in alerts:
        title = label.get(a.get("type"), a.get("type", "Alert"))
        sev = (a.get("severity") or "unknown").upper()
        lines.append(f"### {title} — {sev}")
        lines.append("")
        lines.append(a.get("evidence", ""))
        lines.append("")
        if a.get("recommendation"):
            lines.append(f"**Recommendation:** {a['recommendation']}")
            lines.append("")
    return lines


def _stats_section(stats: dict) -> list[str]:
    lines = [
        "## Traffic Overview",
        "",
        f"- **Total connections:** {stats.get('total_connections', 0):,}",
        f"- **Unique source IPs:** {stats.get('unique_src_ips', 0):,}",
        f"- **Unique destination IPs:** {stats.get('unique_dst_ips', 0):,}",
        f"- **DNS events:** {stats.get('total_dns', 0):,}",
        f"- **Weird events:** {stats.get('total_weird', 0):,}",
        "",
    ]

    top_ports = stats.get("top_ports", [])
    if top_ports:
        lines += ["### Top Destination Ports", "", "| Port | Service | Connections |", "|---|---|---|"]
        lines += [
            f"| {p['port']} | {p.get('service', 'unknown')} | {p['count']:,} |"
            for p in top_ports
        ]
        lines.append("")

    top_services = stats.get("top_services", [])
    if top_services:
        lines += ["### Top Services", "", "| Service | Connections |", "|---|---|"]
        lines += [f"| {s['name']} | {s['count']:,} |" for s in top_services]
        lines.append("")

    return lines


def generate_markdown_report(job_id: str, include_ai_summary: bool = True) -> str | None:
    """Return a full markdown report for a completed job, or None if not found."""
    result = jobs.get_job_result(job_id)
    if result is None:
        return None

    stats = result.get("stats") or {}
    detections = result.get("detections") or {}
    total_alerts = sum(len(v) for v in detections.values())

    generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"# PacketIQ Analysis Report — {result['pcap']}",
        "",
        f"_Generated {generated}_",
        "",
        f"**Capture:** {result['pcap']}  ",
        f"**Detections:** {total_alerts} alert{'s' if total_alerts != 1 else ''}  ",
        "",
        "---",
        "",
    ]

    if include_ai_summary:
        try:
            question = (
                "Give a brief executive summary of this capture: what the traffic is, "
                "any security concerns, and the top recommended next steps."
            )
            rag = query_rag_context(job_id, question)
            summary = analyze_evidence(question, result.get("evidence", ""), rag)
            lines += ["## Executive Summary", "", summary, "", "---", ""]
        except Exception:
            logger.exception("Report AI summary failed for job %s", job_id)

    lines += _stats_section(stats)
    lines += ["---", "", "## Threat Detections", ""]
    lines += _detection_lines(detections)
    lines += [
        "",
        "---",
        "",
        f"## Capture Evidence Summary",
        "",
        "```",
        result.get("evidence", "").strip(),
        "```",
        "",
        "_Report produced by PacketIQ._",
    ]

    return "\n".join(lines)
