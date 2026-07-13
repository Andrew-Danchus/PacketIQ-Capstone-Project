"""Run Zeek against a PCAP, producing JSON logs in a per-capture directory."""

import logging
import shutil
import subprocess
from pathlib import Path

from backend.config import LOG_BASE_DIR, PROJECT_ROOT

logger = logging.getLogger(__name__)

ZEEK_TIMEOUT_SECS = 600


def get_log_dir(pcap_path: Path) -> Path:
    """Return the log directory for the given PCAP (logs/<pcap_stem>/)."""
    return LOG_BASE_DIR / pcap_path.stem


def run_zeek_on_pcap(pcap_path: Path, log_dir: Path) -> None:
    """Parse a PCAP with Zeek. Raises RuntimeError on failure."""
    log_dir.mkdir(parents=True, exist_ok=True)

    if Path("/.dockerenv").exists():
        cmd = [
            "zeek",
            "-C",
            "-r",
            str(pcap_path),
            "LogAscii::use_json=T",
            f"Log::default_logdir={log_dir}",
        ]
    elif shutil.which("zeek"):
        cmd = [
            "zeek",
            "-C",
            "-r",
            str(pcap_path),
            "LogAscii::use_json=T",
            f"Log::default_logdir={log_dir}",
        ]
    elif shutil.which("docker"):
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{PROJECT_ROOT}:/zeek",
            "zeek/zeek:latest",
            "zeek",
            "-C",
            "-r",
            f"/zeek/pcaps/{pcap_path.name}",
            "LogAscii::use_json=T",
            f"Log::default_logdir=/zeek/logs/{pcap_path.stem}",
        ]
    else:
        raise RuntimeError("Neither zeek nor docker is available to parse the PCAP.")

    logger.debug("Running Zeek: %s", " ".join(cmd))

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=ZEEK_TIMEOUT_SECS,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Zeek failed: {result.stderr.strip()}")
