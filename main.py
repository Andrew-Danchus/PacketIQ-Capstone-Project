from pathlib import Path
import subprocess
import json
from collections import Counter, defaultdict

from backend.ollama.service import analyze_evidence


PROJECT_ROOT = Path(__file__).resolve().parent
PCAP_DIR = PROJECT_ROOT / "pcaps"
LOG_DIR = PROJECT_ROOT / "logs"


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


def clear_logs_folder():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    for file in LOG_DIR.iterdir():
        if file.is_file():
            try:
                file.unlink()
            except Exception as e:
                print(f"Could not delete {file.name}: {e}")


def run_zeek_on_pcap(pcap_path: Path):
    clear_logs_folder()

    print(f"\nRunning Zeek on: {pcap_path.name}")
    print("This may take a moment...\n")

    project_root_str = str(PROJECT_ROOT).replace("\\", "/")

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{project_root_str}:/zeek",
        "zeek/zeek",
        "zeek",
        "-C",
        "-r", f"/zeek/pcaps/{pcap_path.name}",
        "LogAscii::use_json=T",
        "Log::default_logdir=/zeek/logs"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("Zeek failed.")
        print(result.stderr)
        return False

    log_files = sorted(LOG_DIR.glob("*.log"))
    if not log_files:
        print("Zeek finished, but no .log files were found in the logs folder.")
        return False

    print("Zeek parsing complete.\n")
    print("Generated log files:")
    for log_file in log_files:
        print(f"- {log_file.name} ({log_file.stat().st_size} bytes)")

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


def summarize_logs():
    conn_log = LOG_DIR / "conn.log"
    weird_log = LOG_DIR / "weird.log"
    packet_filter_log = LOG_DIR / "packet_filter.log"
    dns_log = LOG_DIR / "dns.log"
    notice_log = LOG_DIR / "notice.log"

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


def ask_next_action():
    print("\nWhat would you like to do next?")
    print("1. Ask another question about this same PCAP")
    print("2. Analyze a different PCAP")
    print("3. Exit")

    while True:
        choice = input("\nEnter 1, 2, or 3: ").strip()
        if choice in {"1", "2", "3"}:
            return choice
        print("Please enter 1, 2, or 3.")


def analyze_single_pcap():
    pcaps = list_pcap_files()
    selected_pcap = choose_pcap_file(pcaps)

    if not selected_pcap:
        return "exit"

    success = run_zeek_on_pcap(selected_pcap)
    if not success:
        return "repeat_pcap"

    evidence = summarize_logs()

    print("\n=== PARSED SUMMARY ===\n")
    print(evidence)

    while True:
        user_question = ask_user_question()

        print("\n=== OLLAMA ANALYSIS ===\n")
        try:
            answer = analyze_evidence(user_question, evidence)
            print(answer)
        except Exception as e:
            print(f"Ollama analysis failed: {e}")

        next_action = ask_next_action()

        if next_action == "1":
            continue
        if next_action == "2":
            return "new_pcap"
        return "exit"


def main():
    print("=== PacketIQ CLI ===")

    while True:
        result = analyze_single_pcap()

        if result == "new_pcap":
            continue
        if result == "repeat_pcap":
            continue
        break

    print("\nExiting PacketIQ CLI.")


if __name__ == "__main__":
    main()