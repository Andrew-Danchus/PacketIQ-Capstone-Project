"""Interactive CLI for PacketIQ: analyze a PCAP and ask questions from the terminal.

Usage: python -m backend.cli
"""

import logging

from backend.config import PCAP_DIR, setup_logging
from backend.ollama.service import analyze_evidence
from backend.pipeline import analyze_pcap
from backend.rag.pipeline import query_rag_context
from backend.rag.sql_context import build_sql_context

logger = logging.getLogger(__name__)


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


def main():
    setup_logging()
    print("=== PacketIQ CLI ===")

    selected_pcap = choose_pcap_file(list_pcap_files())
    if not selected_pcap:
        return

    result = analyze_pcap(selected_pcap)

    print("\n=== PARSED SUMMARY ===\n")
    print(result["evidence"])

    summary = result["detections"]
    print("\n=== DETECTIONS ===")
    print(f"Port scans:  {len(summary['port_scans'])}")
    print(f"DDoS:        {len(summary['ddos'])}")
    print(f"Brute force: {len(summary['brute_force'])}")

    print("\n=== PROCESSING TIME ===")
    for step, secs in result["timings"].items():
        print(f"{step:<12} {secs:.2f}s")

    print("\nAsk questions about this PCAP (blank line to exit).")
    while True:
        question = input("\n> ").strip()
        if not question:
            break
        try:
            sql_context = build_sql_context(result["job_id"], question)
            rag_context = query_rag_context(result["job_id"], question)
            answer = analyze_evidence(question, result["evidence"], rag_context, sql_context)
            print(f"\n{answer}")
        except Exception as e:
            print(f"AI analysis failed: {e}")


if __name__ == "__main__":
    main()
