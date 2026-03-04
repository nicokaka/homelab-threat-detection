#!/usr/bin/env python3
"""
custom_detector.py — SSH Brute-Force Detection Engine

A custom intrusion detection sensor that monitors SSH authentication logs
in real-time, identifies brute-force attack patterns using a sliding window
algorithm, and generates structured alerts mapped to MITRE ATT&CK T1110.001.

Supports:
  - Real-time log monitoring (tail -f equivalent)
  - Batch analysis of historical logs
  - Configurable thresholds via CLI or YAML
  - SIEM-compatible JSON alert output
  - Active response via iptables (IPS mode)

Usage:
  python custom_detector.py --help
  python custom_detector.py --log /var/log/auth.log --threshold 5 --window 120
  python custom_detector.py --log /var/log/auth.log --auto-block --output alerts.json

Author: Nicolas Oliveira
MITRE ATT&CK: T1110.001 (Password Guessing)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
import yaml
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, TextIO

# Local imports
sys.path.insert(0, str(Path(__file__).parent))
from config import (
    AUTH_FAIL_PATTERN,
    BANNER,
    COLORS,
    DEFAULT_LOG_PATH,
    DEFAULT_OUTPUT_FILE,
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW_SECONDS,
    IPTABLES_BLOCK_CMD,
)
from models import AlertEvent, AttackSession

# ──────────────────────────────────────────────
# Logger configuration
# ──────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ssh-detector")

# ──────────────────────────────────────────────
# Globals
# ──────────────────────────────────────────────

running: bool = True
stats: dict[str, int] = {
    "lines_processed": 0,
    "failed_attempts_detected": 0,
    "alerts_generated": 0,
    "ips_blocked": 0,
}


def signal_handler(sig: int, frame) -> None:
    """Handle graceful shutdown on SIGINT/SIGTERM."""
    global running
    running = False
    print(f"\n{COLORS['YELLOW']}[!] Shutting down detector...{COLORS['RESET']}")


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ──────────────────────────────────────────────
# Core Detection Engine
# ──────────────────────────────────────────────


class SSHBruteForceDetector:
    """SSH brute-force detection engine using sliding window analysis.

    Monitors authentication logs for patterns of repeated failed SSH login
    attempts from the same source IP within a configurable time window.

    Attributes:
        threshold: Number of failed attempts to trigger an alert.
        window_seconds: Time window for sliding window analysis.
        log_path: Path to the authentication log file.
        output_file: Path to write JSON alerts (None = stdout only).
        auto_block: Whether to auto-block IPs via iptables.
        sessions: Active attack sessions indexed by source IP.
        blocked_ips: Set of IPs that have been blocked.
    """

    def __init__(
        self,
        threshold: int = DEFAULT_THRESHOLD,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        log_path: str = DEFAULT_LOG_PATH,
        output_file: Optional[str] = DEFAULT_OUTPUT_FILE,
        auto_block: bool = False,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.log_path = log_path
        self.output_file = output_file
        self.auto_block = auto_block
        self.sessions: dict[str, AttackSession] = defaultdict(
            lambda: AttackSession(source_ip="")
        )
        self.blocked_ips: set[str] = set()
        self._compiled_pattern: re.Pattern = re.compile(AUTH_FAIL_PATTERN)
        self._current_year: int = datetime.now().year

    def parse_log_line(self, line: str) -> Optional[dict]:
        """Parse a single auth.log line for failed SSH authentication.

        Args:
            line: Raw log line from auth.log.

        Returns:
            Dictionary with parsed fields, or None if not a match.
        """
        match = self._compiled_pattern.search(line)
        if not match:
            return None

        month_str, day, time_str, hostname, username, source_ip = match.groups()

        # Parse timestamp (auth.log doesn't include year)
        try:
            timestamp = datetime.strptime(
                f"{self._current_year} {month_str} {day} {time_str}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            return None

        return {
            "timestamp": timestamp,
            "hostname": hostname,
            "username": username,
            "source_ip": source_ip,
            "raw_line": line,
        }

    def process_line(self, line: str) -> Optional[AlertEvent]:
        """Process a single log line through the detection engine.

        Parses the line, updates the corresponding attack session,
        and generates an alert if the threshold is exceeded.

        Args:
            line: Raw log line to process.

        Returns:
            AlertEvent if threshold was exceeded, None otherwise.
        """
        stats["lines_processed"] += 1

        parsed = self.parse_log_line(line)
        if not parsed:
            return None

        stats["failed_attempts_detected"] += 1
        source_ip = parsed["source_ip"]

        # Skip already blocked IPs
        if source_ip in self.blocked_ips:
            return None

        # Update or create the attack session
        session = self.sessions[source_ip]
        session.source_ip = source_ip
        session.add_attempt(
            timestamp=parsed["timestamp"],
            username=parsed["username"],
            raw_line=parsed["raw_line"],
        )
        session.prune_old_attempts(self.window_seconds)

        # Check threshold
        if session.attempt_count >= self.threshold and not session.alerted:
            session.alerted = True
            alert = self._generate_alert(session)
            return alert

        return None

    def _generate_alert(self, session: AttackSession) -> AlertEvent:
        """Generate a structured alert from an attack session.

        Args:
            session: The attack session that triggered the alert.

        Returns:
            Fully populated AlertEvent.
        """
        severity = AlertEvent.classify_severity(
            session.attempt_count, self.window_seconds
        )

        alert = AlertEvent(
            source_ip=session.source_ip,
            failed_attempts=session.attempt_count,
            time_window_seconds=self.window_seconds,
            first_seen=session.first_seen or "",
            last_seen=session.last_seen or "",
            raw_log_samples=session.log_samples.copy(),
            usernames_targeted=session.usernames.copy(),
            severity=severity,
        )

        stats["alerts_generated"] += 1
        return alert

    def handle_alert(self, alert: AlertEvent) -> None:
        """Process a generated alert: display, save, and optionally block.

        Args:
            alert: The alert event to handle.
        """
        # Display to terminal
        self._print_alert(alert)

        # Save to file if configured
        if self.output_file:
            self._save_alert(alert)

        # Auto-block if IPS mode is enabled
        if self.auto_block:
            self._block_ip(alert.source_ip)

    def _print_alert(self, alert: AlertEvent) -> None:
        """Display a formatted alert in the terminal.

        Args:
            alert: The alert event to display.
        """
        c = COLORS
        severity_color = c["RED"] if alert.severity in ("CRITICAL", "HIGH") else c["YELLOW"]

        print(f"\n{c['RED']}{c['BOLD']}{'═' * 62}{c['RESET']}")
        print(f"{c['RED']}{c['BOLD']}  🚨 BRUTE-FORCE ALERT DETECTED{c['RESET']}")
        print(f"{c['RED']}{c['BOLD']}{'═' * 62}{c['RESET']}")
        print(f"  {c['CYAN']}Alert ID:{c['RESET']}      {alert.alert_id}")
        print(f"  {c['CYAN']}Timestamp:{c['RESET']}     {alert.timestamp}")
        print(f"  {c['CYAN']}Source IP:{c['RESET']}      {c['RED']}{alert.source_ip}{c['RESET']}")
        print(f"  {c['CYAN']}Severity:{c['RESET']}       {severity_color}{alert.severity}{c['RESET']}")
        print(f"  {c['CYAN']}Attempts:{c['RESET']}       {alert.failed_attempts} in {alert.time_window_seconds}s")
        print(f"  {c['CYAN']}Users Targeted:{c['RESET']} {', '.join(alert.usernames_targeted)}")
        print(f"  {c['CYAN']}MITRE:{c['RESET']}          {alert.mitre_technique}")
        print(f"  {c['CYAN']}Action:{c['RESET']}         {alert.action_taken}")
        print(f"{c['RED']}{c['BOLD']}{'═' * 62}{c['RESET']}\n")

    def _save_alert(self, alert: AlertEvent) -> None:
        """Append alert to the JSON output file.

        Args:
            alert: The alert event to save.
        """
        try:
            # Read existing alerts
            alerts_list = []
            if os.path.exists(self.output_file):
                with open(self.output_file, "r") as f:
                    try:
                        alerts_list = json.load(f)
                    except json.JSONDecodeError:
                        alerts_list = []

            # Append new alert
            alerts_list.append(alert.to_dict())

            # Write back
            with open(self.output_file, "w") as f:
                json.dump(alerts_list, f, indent=2, ensure_ascii=False)

            logger.info(f"Alert saved to {self.output_file}")

        except OSError as e:
            logger.error(f"Failed to save alert: {e}")

    def _block_ip(self, ip: str) -> None:
        """Block an IP address using iptables (requires root).

        Args:
            ip: The IP address to block.
        """
        if ip in self.blocked_ips:
            return

        cmd = IPTABLES_BLOCK_CMD.format(ip=ip)
        logger.warning(f"🔒 AUTO-BLOCK: Executing '{cmd}'")

        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                stats["ips_blocked"] += 1
                logger.info(f"✅ Successfully blocked {ip}")
            else:
                logger.error(f"❌ Failed to block {ip}: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            logger.error(f"❌ Timeout blocking {ip}")
        except PermissionError:
            logger.error(f"❌ Permission denied — run with sudo for auto-block")

    def monitor_realtime(self) -> None:
        """Monitor the log file in real-time (tail -f equivalent).

        Uses file seek to efficiently follow new log entries.
        """
        logger.info(f"🔍 Monitoring {self.log_path} in real-time...")
        logger.info(f"   Threshold: {self.threshold} attempts / {self.window_seconds}s window")
        logger.info(f"   Auto-block: {'ENABLED (IPS)' if self.auto_block else 'DISABLED (IDS)'}")

        try:
            with open(self.log_path, "r") as f:
                # Jump to end of file
                f.seek(0, 2)

                while running:
                    line = f.readline()
                    if line:
                        alert = self.process_line(line)
                        if alert:
                            self.handle_alert(alert)
                    else:
                        time.sleep(0.5)  # No new data, wait before retry

        except FileNotFoundError:
            logger.error(f"❌ Log file not found: {self.log_path}")
            sys.exit(1)
        except PermissionError:
            logger.error(f"❌ Permission denied: {self.log_path} — try running with sudo")
            sys.exit(1)

    def analyze_batch(self) -> list[AlertEvent]:
        """Analyze an entire log file for brute-force patterns.

        Processes all lines in the file (historical analysis).

        Returns:
            List of alerts generated during analysis.
        """
        logger.info(f"📂 Analyzing {self.log_path} (batch mode)...")

        alerts: list[AlertEvent] = []

        try:
            with open(self.log_path, "r") as f:
                for line in f:
                    alert = self.process_line(line)
                    if alert:
                        alerts.append(alert)
                        self.handle_alert(alert)

        except FileNotFoundError:
            logger.error(f"❌ Log file not found: {self.log_path}")
            sys.exit(1)
        except PermissionError:
            logger.error(f"❌ Permission denied: {self.log_path}")
            sys.exit(1)

        return alerts

    def print_summary(self) -> None:
        """Print detection session statistics."""
        c = COLORS
        print(f"\n{c['CYAN']}{'─' * 40}{c['RESET']}")
        print(f"{c['BOLD']}  📊 Detection Summary{c['RESET']}")
        print(f"{c['CYAN']}{'─' * 40}{c['RESET']}")
        print(f"  Lines processed:        {stats['lines_processed']}")
        print(f"  Failed attempts found:  {stats['failed_attempts_detected']}")
        print(f"  Alerts generated:       {c['RED']}{stats['alerts_generated']}{c['RESET']}")
        print(f"  IPs auto-blocked:       {stats['ips_blocked']}")
        print(f"  Unique source IPs:      {len(self.sessions)}")
        print(f"{c['CYAN']}{'─' * 40}{c['RESET']}\n")


# ──────────────────────────────────────────────
# Configuration Loader
# ──────────────────────────────────────────────


def load_config(config_path: str) -> dict:
    """Load configuration from a YAML file.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        Configuration dictionary.
    """
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}
            logger.info(f"📋 Configuration loaded from {config_path}")
            return config
    except FileNotFoundError:
        logger.warning(f"Config file not found: {config_path}, using defaults")
        return {}
    except yaml.YAMLError as e:
        logger.error(f"Invalid YAML config: {e}")
        return {}


# ──────────────────────────────────────────────
# CLI Argument Parser
# ──────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="custom_detector",
        description=(
            "🛡️ SSH Brute-Force Detection Engine — "
            "Real-time intrusion detection sensor mapped to MITRE ATT&CK T1110.001"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --log /var/log/auth.log\n"
            "  %(prog)s --log /var/log/auth.log --threshold 10 --window 60\n"
            "  %(prog)s --log /var/log/auth.log --output alerts.json --auto-block\n"
            "  %(prog)s --log sample.log --batch\n"
        ),
    )

    parser.add_argument(
        "--log",
        type=str,
        default=DEFAULT_LOG_PATH,
        help=f"Path to the SSH auth log file (default: {DEFAULT_LOG_PATH})",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=f"Failed attempts threshold to trigger alert (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=DEFAULT_WINDOW_SECONDS,
        help=f"Sliding window size in seconds (default: {DEFAULT_WINDOW_SECONDS})",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=DEFAULT_OUTPUT_FILE,
        help="Path to save alerts as JSON (default: stdout only)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "--auto-block",
        action="store_true",
        default=False,
        help="Enable IPS mode: auto-block attacker IPs via iptables (requires root)",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        default=False,
        help="Analyze entire log file instead of real-time monitoring",
    )

    return parser


# ──────────────────────────────────────────────
# Main Entry Point
# ──────────────────────────────────────────────


def main() -> None:
    """Main entry point for the SSH Brute-Force Detection Engine."""
    print(BANNER)

    parser = build_parser()
    args = parser.parse_args()

    # Load YAML config (CLI args take precedence)
    config = {}
    if args.config:
        config = load_config(args.config)

    threshold = args.threshold if args.threshold != DEFAULT_THRESHOLD else config.get("threshold", DEFAULT_THRESHOLD)
    window = args.window if args.window != DEFAULT_WINDOW_SECONDS else config.get("window_seconds", DEFAULT_WINDOW_SECONDS)
    log_path = args.log if args.log != DEFAULT_LOG_PATH else config.get("log_path", DEFAULT_LOG_PATH)
    output_file = args.output or config.get("output_file", DEFAULT_OUTPUT_FILE)
    auto_block = args.auto_block or config.get("auto_block", False)

    # Initialize detector
    detector = SSHBruteForceDetector(
        threshold=threshold,
        window_seconds=window,
        log_path=log_path,
        output_file=output_file,
        auto_block=auto_block,
    )

    # Run in selected mode
    try:
        if args.batch:
            alerts = detector.analyze_batch()
            logger.info(f"Batch analysis complete. {len(alerts)} alert(s) generated.")
        else:
            detector.monitor_realtime()
    except KeyboardInterrupt:
        pass
    finally:
        detector.print_summary()


if __name__ == "__main__":
    main()
