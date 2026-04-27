from pathlib import Path
import subprocess
import json
from collections import Counter, defaultdict
import time
import os
import uuid
import shutil

from backend.db.ingest_logs import ingest_job_logs
from backend.ollama.service import analyze_evidence
from backend.rag.pipeline import build_rag_index, query_rag_context
from backend.detection.detection import run_detections


PROJECT_ROOT = Path(__file__).resolve().parent
PCAP_DIR = Path(os.getenv("PCAP_DIR", str(PROJECT_ROOT / "pcaps")))
LOG_BASE_DIR = Path(os.getenv("LOG_DIR", str(PROJECT_ROOT / "logs")))


def timed_step(step_name, func, *args, **kwargs):
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    elapsed = end - start
    print(f"[TIME] {step_name}: {elapsed:.2f} seconds")
    return result, elapsed

def log_ingestion(pcap_path: Path, log_dir: Path) -> str | None:
    job_id = str(uuid.uuid4())
    dsn = os.getenv("DATABASE_URL")

    if not dsn:
        print("DATABASE_URL not set. Logs will not be ingested.")
        return None

    try:
        ingest_job_logs(
            job_id=job_id,
            filename=pcap_path.name,
            file_size_bytes=pcap_path.stat().st_size,
            log_dir=log_dir,
            dsn=dsn,
        )
        print(f"\nLogs ingested into database with ID: {job_id}")
        return job_id
    except Exception as e:
        print(f"Error ingesting logs into database: {e}")
        return None

def list_pcap_files():
    if not PCAP_DIR.exists():
        return []

    pcaps = []
    for ext in ("*.pcap", "*.pcapng", "*.cap"):
        pcaps.extend(PCAP_DIR.glob(ext))

    return sorted(pcaps)


def choose_pcap_file(pcaps):
    if not pcaps:
        print(f"No PCAP files found in: {PCAP_DIR}")
        return None

    print("\nAvailable PCAP files:\n")
    for i, pcap in enumerate(pcaps, start=1):
        size_mb = pcap.stat().st_size / (1024 * 1024)
        print(f"{i}. {pcap.name} ({size_mb:.2f} MB)")

    while True:
        choice = input("\nEnter the number of the PCAP to analyze: ").strip()

        if not choice.isdigit():
            print("Please enter a valid number.")
            continue

        choice = int(choice)
        if 1 <= choice <= len(pcaps):
            return pcaps[choice - 1]

        print("Choice out of range.")


def get_log_dir(pcap_path: Path) -> Path:
    """Return the log directory for the given PCAP (logs/<pcap_stem>/)."""
    return LOG_BASE_DIR / pcap_path.stem


def logs_exist(log_dir: Path) -> bool:
    """Return True if the per-PCAP log directory already contains .log files."""
    return log_dir.is_dir() and any(log_dir.glob("*.log"))


def run_zeek_on_pcap(pcap_path: Path, log_dir: Path) -> bool:
    log_dir.mkdir(parents=True, exist_ok=True)

    # If running inside Docker backend container, use Zeek directly
    if Path("/.dockerenv").exists():
        cmd = [
            "zeek",
            "-C",
            "-r",
            str(pcap_path),
            f"Log::default_logdir={str(log_dir)}",
        ]

    # If running locally on Windows and Docker is installed, use Docker
    elif shutil.which("docker"):
        project_root = Path(__file__).resolve().parent
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{project_root}:/zeek",
            "zeek/zeek:latest",
            "zeek",
            "-C",
            "-r",
            f"/zeek/pcaps/{pcap_path.name}",
            f"Log::default_logdir=/zeek/logs/{pcap_path.stem}",
        ]

    else:
        raise RuntimeError("Neither zeek nor docker was found.")

    print("DEBUG: running command:", " ".join(cmd))

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
    )

    print("DEBUG: zeek stdout:", result.stdout)
    print("DEBUG: zeek stderr:", result.stderr)

    if result.returncode != 0:
        raise RuntimeError(f"Zeek failed: {result.stderr}")

    return True
def load_json_log(file_path: Path):
    records = []

    if not file_path.exists():
        return records

    with file_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records


def summarize_logs(log_dir: Path):
    conn_log = log_dir / "conn.log"
    weird_log = log_dir / "weird.log"
    packet_filter_log = log_dir / "packet_filter.log"
    dns_log = log_dir / "dns.log"
    notice_log = log_dir / "notice.log"

    conn_records = load_json_log(conn_log)
    weird_records = load_json_log(weird_log)
    packet_filter_records = load_json_log(packet_filter_log)
    dns_records = load_json_log(dns_log)
    notice_records = load_json_log(notice_log)

    src_ips = Counter()
    dst_ips = Counter()
    services = Counter()
    ports = Counter()
    port_service_map = defaultdict(Counter)
    port_pair_map = defaultdict(Counter)
    src_to_port_map = defaultdict(Counter)
    conn_state_counts = Counter()

    for record in conn_records:
        src = record.get("id.orig_h")
        dst = record.get("id.resp_h")
        service = record.get("service")
        port = record.get("id.resp_p")
        conn_state = record.get("conn_state")

        if src:
            src_ips[src] += 1
        if dst:
            dst_ips[dst] += 1
        if service:
            services[service] += 1
        if port is not None:
            port_str = str(port)
            ports[port_str] += 1
            if service:
                port_service_map[port_str][service] += 1
            if src and dst:
                port_pair_map[port_str][f"{src} -> {dst}"] += 1
            if src:
                src_to_port_map[port_str][src] += 1
        if conn_state:
            conn_state_counts[conn_state] += 1

    weird_names = Counter()
    for record in weird_records:
        name = record.get("name")
        if name:
            weird_names[name] += 1

    dns_queries = Counter()
    for record in dns_records:
        query = record.get("query")
        if query:
            dns_queries[query] += 1

    summary = []
    summary.append("PCAP forensic summary from Zeek logs")
    summary.append("")
    summary.append(f"Total connections: {len(conn_records)}")
    summary.append(f"Total weird events: {len(weird_records)}")
    summary.append(f"Total packet filter events: {len(packet_filter_records)}")
    summary.append(f"Total DNS events: {len(dns_records)}")
    summary.append(f"Total notice events: {len(notice_records)}")
    summary.append(f"Unique source IPs: {len(src_ips)}")
    summary.append(f"Unique destination IPs: {len(dst_ips)}")

    summary.append("\nTop source IPs:")
    if src_ips:
        for ip, count in src_ips.most_common(5):
            summary.append(f"- {ip}: {count} connections")
    else:
        summary.append("- None")

    summary.append("\nTop destination IPs:")
    if dst_ips:
        for ip, count in dst_ips.most_common(5):
            summary.append(f"- {ip}: {count} connections")
    else:
        summary.append("- None")

    summary.append("\nTop services:")
    if services:
        for service, count in services.most_common(10):
            summary.append(f"- {service}: {count}")
    else:
        summary.append("- None")

    summary.append("\nTop destination ports:")
    if ports:
        for port, count in ports.most_common(10):
            top_service = "unknown"
            if port_service_map[port]:
                top_service = port_service_map[port].most_common(1)[0][0]

            top_pair = "unknown"
            if port_pair_map[port]:
                top_pair = port_pair_map[port].most_common(1)[0][0]

            top_src = "unknown"
            if src_to_port_map[port]:
                top_src = src_to_port_map[port].most_common(1)[0][0]

            summary.append(
                f"- Port {port}: {count} connections | "
                f"Likely service: {top_service} | "
                f"Top source: {top_src} | "
                f"Most common path: {top_pair}"
            )
    else:
        summary.append("- None")

    summary.append("\nConnection states:")
    if conn_state_counts:
        for state, count in conn_state_counts.most_common(10):
            summary.append(f"- {state}: {count}")
    else:
        summary.append("- None")

    summary.append("\nTop weird events:")
    if weird_names:
        for name, count in weird_names.most_common(10):
            summary.append(f"- {name}: {count}")
    else:
        summary.append("- None")

    summary.append("\nTop DNS queries:")
    if dns_queries:
        for query, count in dns_queries.most_common(10):
            summary.append(f"- {query}: {count}")
    else:
        summary.append("- None")

    # Add a short suspicious-pattern section for Ollama
    summary.append("\nPotential indicators observed:")
    indicators_added = False

    if ports:
        most_targeted_port, port_count = ports.most_common(1)[0]
        summary.append(
            f"- Most targeted destination port: {most_targeted_port} with {port_count} connections"
        )
        indicators_added = True

    if src_ips:
        top_src_ip, src_count = src_ips.most_common(1)[0]
        summary.append(
            f"- Most active source IP: {top_src_ip} with {src_count} connections"
        )
        indicators_added = True

    if weird_names:
        weird_name, weird_count = weird_names.most_common(1)[0]
        summary.append(
            f"- Most common weird event: {weird_name} with {weird_count} occurrences"
        )
        indicators_added = True

    if conn_state_counts:
        state, count = conn_state_counts.most_common(1)[0]
        summary.append(
            f"- Most common connection state: {state} with {count} occurrences"
        )
        indicators_added = True

    if not indicators_added:
        summary.append("- No obvious indicators extracted from available Zeek logs")

    return "\n".join(summary)


def ask_user_question():
    print("\nAsk a question about this PCAP.")
    print("Examples:")
    print("- What service is being targeted?")
    print("- Does this look like SSH brute force?")
    print("- Which IP is the most suspicious?")
    print("- What port should I close first?")
    print("- What firewall rule would you recommend?")

    question = input("\nYour question:\n> ").strip()

    if not question:
        question = "Summarize suspicious activity and recommend next investigation steps."

    return question


def main():
    app_start = time.perf_counter()

    print("=== PacketIQ CLI ===")

    pcaps = list_pcap_files()
    selected_pcap = choose_pcap_file(pcaps)

    if not selected_pcap:
        return

    log_dir = get_log_dir(selected_pcap)
    success, zeek_time = timed_step("Zeek parsing", run_zeek_on_pcap, selected_pcap, log_dir)
    if not success:
        return
    job_id = log_ingestion(selected_pcap, log_dir)
    detection_time = 0.0
    detection_results = None
    conn_log_path = log_dir / "conn.log"
    if conn_log_path.exists():
        print("\n=== RUNNING DETECTIONS ===")
        try:
            output_path = PROJECT_ROOT / "output" / "detection.json"
            output_path.parent.mkdir(parents=True, exist_ok=True)
            detection_results, detection_time = timed_step(
                "Detection", run_detections, str(conn_log_path), str(output_path)
            )
        except Exception as e:
            print(f"Detection failed: {e}")

    print("\n=== BUILDING RAG INDEX ===")
    rag_job_id = None
    rag_time = 0.0
    if job_id:
        rag_job_id, rag_time= timed_step("RAG index build", build_rag_index, job_id, log_dir, detection_results)
    else: print("Skipping RAG index due to ingestion failure.")

    evidence, summary_time = timed_step("Log summarization", summarize_logs, log_dir)

    print("\n=== PARSED SUMMARY ===\n")
    print(evidence)

    user_question = ask_user_question()

    print("\n=== OLLAMA ANALYSIS ===\n")
    ollama_time = 0.0
    try:
        rag_context = "no RAG context available"
        if rag_job_id:
            rag_context = query_rag_context(rag_job_id, user_question)
        answer, ollama_time = timed_step("Ollama analysis", analyze_evidence, user_question, evidence, rag_context)
        print(answer)
    except Exception as e:
        print(f"Ollama analysis failed: {e}")

    total_app_time = time.perf_counter() - app_start
    print("\n=== PROCESSING TIME SUMMARY ===")
    print(f"Zeek parsing:       {zeek_time:.2f} seconds")
    print(f"Detection:          {detection_time:.2f} seconds")
    print(f"RAG index build:    {rag_time:.2f} seconds")
    print(f"Log summarization:  {summary_time:.2f} seconds")
    print(f"Ollama analysis:    {ollama_time:.2f} seconds")
    print(f"Total runtime:      {total_app_time:.2f} seconds")


if __name__ == "__main__":
    main()
