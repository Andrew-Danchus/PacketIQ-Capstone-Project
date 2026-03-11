from pathlib import Path
import subprocess
import json
from collections import Counter

from backend.ollama.service import explain_alert


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
        f"Log::default_logdir=/zeek/logs"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("Zeek failed.")
        print(result.stderr)
        return False

    print("Zeek parsing complete.\n")

    log_files = sorted(LOG_DIR.glob("*.log"))
    if not log_files:
        print("No log files were created in the logs folder.")
        return False

    print("Generated log files:")
    for f in log_files:
        print(f"- {f.name} ({f.stat().st_size} bytes)")

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

    conn_records = load_json_log(conn_log)
    weird_records = load_json_log(weird_log)
    packet_filter_records = load_json_log(packet_filter_log)

    print("\nDebug log counts:")
    print(f"conn.log records: {len(conn_records)}")
    print(f"weird.log records: {len(weird_records)}")
    print(f"packet_filter.log records: {len(packet_filter_records)}")

    src_ips = Counter()
    dst_ips = Counter()
    services = Counter()
    ports = Counter()

    for record in conn_records:
        src = record.get("id.orig_h")
        dst = record.get("id.resp_h")
        service = record.get("service")
        port = record.get("id.resp_p")

        if src:
            src_ips[src] += 1
        if dst:
            dst_ips[dst] += 1
        if service:
            services[service] += 1
        if port is not None:
            ports[str(port)] += 1

    summary = []
    summary.append(f"Total connections: {len(conn_records)}")
    summary.append(f"Total weird events: {len(weird_records)}")
    summary.append(f"Total packet filter events: {len(packet_filter_records)}")
    summary.append(f"Unique source IPs: {len(src_ips)}")
    summary.append(f"Unique destination IPs: {len(dst_ips)}")

    summary.append("\nTop source IPs:")
    for ip, count in src_ips.most_common(5):
        summary.append(f"- {ip}: {count} connections")

    summary.append("\nTop destination IPs:")
    for ip, count in dst_ips.most_common(5):
        summary.append(f"- {ip}: {count} connections")

    summary.append("\nTop services:")
    for svc, count in services.most_common(5):
        summary.append(f"- {svc}: {count}")

    summary.append("\nTop destination ports:")
    for port, count in ports.most_common(10):
        summary.append(f"- {port}: {count}")

    if weird_records:
        weird_names = Counter()
        for record in weird_records:
            name = record.get("name")
            if name:
                weird_names[name] += 1

        summary.append("\nTop weird events:")
        for name, count in weird_names.most_common(10):
            summary.append(f"- {name}: {count}")

    return "\n".join(summary)


def main():
    print("=== PacketIQ CLI ===")

    pcaps = list_pcap_files()
    selected_pcap = choose_pcap_file(pcaps)

    if not selected_pcap:
        return

    success = run_zeek_on_pcap(selected_pcap)
    if not success:
        return

    evidence = summarize_logs()

    print("\n=== PARSED SUMMARY ===\n")
    print(evidence)

    user_question = input(
        "\nEnter the analysis request for Ollama\n"
        "(example: 'Summarize suspicious activity and recommend next steps'):\n> "
    ).strip()

    if not user_question:
        user_question = "Summarize suspicious activity, assign severity, and recommend next investigation steps."

    alert_type = f"PCAP Analysis Request: {user_question}"

    print("\n=== OLLAMA ANALYSIS ===\n")
    try:
        answer = explain_alert(alert_type, evidence)
        print(answer)
    except Exception as e:
        print(f"Ollama analysis failed: {e}")


if __name__ == "__main__":
    main()