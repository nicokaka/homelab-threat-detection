#!/usr/bin/env python3
"""
test_detector.py — Unit tests for the SSH Brute-Force Detection Engine.

Tests cover:
  - Log line parsing (valid and invalid entries)
  - Sliding window attack session management
  - Alert generation at threshold
  - Severity classification
  - Batch analysis with sample logs
  - Alert JSON serialization

Run:
  python -m pytest tests/test_detector.py -v
  python tests/test_detector.py  # standalone
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime
from pathlib import Path

# Add src/ to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from config import DEFAULT_THRESHOLD, DEFAULT_WINDOW_SECONDS
from models import AlertEvent, AttackSession
from custom_detector import SSHBruteForceDetector


class TestLogParsing(unittest.TestCase):
    """Test auth.log line parsing."""

    def setUp(self) -> None:
        self.detector = SSHBruteForceDetector(log_path="dummy")

    def test_parse_valid_failed_password(self) -> None:
        """Should parse a standard failed password log line."""
        line = "Mar  3 11:00:01 ubuntu-server sshd[2001]: Failed password for root from 192.168.10.5 port 44101 ssh2"
        result = self.detector.parse_log_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result["source_ip"], "192.168.10.5")
        self.assertEqual(result["username"], "root")
        self.assertIsInstance(result["timestamp"], datetime)

    def test_parse_invalid_user_attempt(self) -> None:
        """Should parse a failed attempt with 'invalid user' prefix."""
        line = "Mar  3 11:00:05 ubuntu-server sshd[2003]: Failed password for invalid user test from 192.168.10.5 port 44103 ssh2"
        result = self.detector.parse_log_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result["source_ip"], "192.168.10.5")
        self.assertEqual(result["username"], "test")

    def test_parse_accepted_password_returns_none(self) -> None:
        """Should NOT parse successful logins (no match)."""
        line = "Mar  3 10:00:01 ubuntu-server sshd[1001]: Accepted password for admin from 192.168.10.100 port 52341 ssh2"
        result = self.detector.parse_log_line(line)

        self.assertIsNone(result)

    def test_parse_unrelated_log_returns_none(self) -> None:
        """Should NOT parse non-SSH log lines."""
        line = "Mar  3 10:00:01 ubuntu-server CRON[999]: pam_unix(cron:session): session opened"
        result = self.detector.parse_log_line(line)

        self.assertIsNone(result)

    def test_parse_empty_line_returns_none(self) -> None:
        """Should handle empty lines gracefully."""
        result = self.detector.parse_log_line("")
        self.assertIsNone(result)


class TestAttackSession(unittest.TestCase):
    """Test the AttackSession sliding window model."""

    def test_add_attempts(self) -> None:
        """Should track attempts and unique usernames."""
        session = AttackSession(source_ip="10.0.0.1")
        ts = datetime(2026, 3, 3, 11, 0, 0)

        session.add_attempt(ts, "root", "line1")
        session.add_attempt(ts, "admin", "line2")
        session.add_attempt(ts, "root", "line3")  # duplicate username

        self.assertEqual(session.attempt_count, 3)
        self.assertEqual(session.usernames, ["root", "admin"])

    def test_prune_old_attempts(self) -> None:
        """Should remove attempts outside the time window."""
        session = AttackSession(source_ip="10.0.0.1")

        # Add attempts spread over 5 minutes
        for i in range(6):
            ts = datetime(2026, 3, 3, 11, i, 0)
            session.add_attempt(ts, "root", f"line{i}")

        # Prune with 120-second window (should keep last ~2 minutes)
        session.prune_old_attempts(120)

        self.assertLessEqual(session.attempt_count, 3)

    def test_log_samples_max_five(self) -> None:
        """Should keep a maximum of 5 raw log samples."""
        session = AttackSession(source_ip="10.0.0.1")
        ts = datetime(2026, 3, 3, 11, 0, 0)

        for i in range(10):
            session.add_attempt(ts, "root", f"log_line_{i}")

        self.assertEqual(len(session.log_samples), 5)


class TestSeverityClassification(unittest.TestCase):
    """Test alert severity classification logic."""

    def test_critical_severity(self) -> None:
        """50+ attempts should be CRITICAL."""
        self.assertEqual(AlertEvent.classify_severity(50, 60), "CRITICAL")

    def test_high_severity(self) -> None:
        """20+ attempts should be HIGH."""
        self.assertEqual(AlertEvent.classify_severity(20, 120), "HIGH")

    def test_medium_severity(self) -> None:
        """10+ attempts should be MEDIUM."""
        self.assertEqual(AlertEvent.classify_severity(10, 120), "MEDIUM")

    def test_low_severity(self) -> None:
        """Few attempts over long window should be LOW."""
        self.assertEqual(AlertEvent.classify_severity(3, 300), "LOW")


class TestAlertEvent(unittest.TestCase):
    """Test AlertEvent model and serialization."""

    def test_alert_creation(self) -> None:
        """Should create alert with all required fields."""
        alert = AlertEvent(
            source_ip="192.168.10.5",
            failed_attempts=10,
            time_window_seconds=120,
            first_seen="2026-03-03T11:00:01",
            last_seen="2026-03-03T11:01:59",
        )

        self.assertEqual(alert.source_ip, "192.168.10.5")
        self.assertEqual(alert.mitre_technique, "Brute Force (T1110)")
        self.assertTrue(alert.alert_id.startswith("SSH-BF-"))

    def test_alert_json_serialization(self) -> None:
        """Should serialize to valid JSON with all MITRE fields."""
        alert = AlertEvent(
            source_ip="10.0.0.15",
            failed_attempts=7,
            time_window_seconds=60,
            first_seen="2026-03-03T13:30:00",
            last_seen="2026-03-03T13:30:12",
            usernames_targeted=["root", "admin"],
        )

        json_str = alert.to_json()
        parsed = json.loads(json_str)

        self.assertEqual(parsed["source_ip"], "10.0.0.15")
        self.assertEqual(parsed["mitre_tactic"], "Credential Access (TA0006)")
        self.assertIn("root", parsed["usernames_targeted"])


class TestDetectorBatchAnalysis(unittest.TestCase):
    """Test full batch analysis pipeline with sample logs."""

    def setUp(self) -> None:
        self.sample_log = str(Path(__file__).parent / "sample_auth.log")
        self.detector = SSHBruteForceDetector(
            threshold=5,
            window_seconds=120,
            log_path=self.sample_log,
            output_file=None,
            auto_block=False,
        )

    def test_batch_detects_brute_force(self) -> None:
        """Should detect brute-force attacks in sample log."""
        alerts = self.detector.analyze_batch()

        # Should detect at least 2 attackers (192.168.10.5 and 10.0.0.15)
        self.assertGreaterEqual(len(alerts), 2)

        # Verify attacker IPs
        alert_ips = [a.source_ip for a in alerts]
        self.assertIn("192.168.10.5", alert_ips)
        self.assertIn("10.0.0.15", alert_ips)

    def test_batch_ignores_normal_activity(self) -> None:
        """Should NOT alert on normal/low-volume activity."""
        alerts = self.detector.analyze_batch()
        alert_ips = [a.source_ip for a in alerts]

        # 192.168.10.50 only has 2 attempts — should NOT trigger
        self.assertNotIn("192.168.10.50", alert_ips)

        # 192.168.10.100 has only accepted logins — should NOT trigger
        self.assertNotIn("192.168.10.100", alert_ips)

    def test_batch_slow_probe_below_threshold(self) -> None:
        """Slow probe (3 attempts over >5 min) should NOT trigger with 120s window."""
        alerts = self.detector.analyze_batch()
        alert_ips = [a.source_ip for a in alerts]

        # 192.168.10.20 has 3 attempts spread over 6 minutes — should NOT trigger
        self.assertNotIn("192.168.10.20", alert_ips)


if __name__ == "__main__":
    unittest.main(verbosity=2)
