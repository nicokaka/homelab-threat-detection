"""
models.py — Data models for SSH brute-force detection alerts.

Uses Python dataclasses for clean, typed, serializable alert structures
compatible with SIEM ingestion (Splunk, Elastic, etc.).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class AlertEvent:
    """Represents a single SSH brute-force detection alert.

    Structured for SIEM compatibility with MITRE ATT&CK mapping.
    """

    source_ip: str
    failed_attempts: int
    time_window_seconds: int
    first_seen: str
    last_seen: str
    raw_log_samples: list[str] = field(default_factory=list)
    usernames_targeted: list[str] = field(default_factory=list)

    # Auto-generated fields
    alert_id: str = field(default_factory=lambda: f"SSH-BF-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    severity: str = "HIGH"

    # MITRE ATT&CK mapping (constant for this detection rule)
    mitre_tactic: str = "Credential Access (TA0006)"
    mitre_technique: str = "Brute Force (T1110)"
    mitre_sub_technique: str = "Password Guessing (T1110.001)"

    # Response
    action_taken: str = "IP logged for review"

    def to_dict(self) -> dict:
        """Convert alert to a dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize alert to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @staticmethod
    def classify_severity(failed_attempts: int, time_window: int) -> str:
        """Classify alert severity based on attempt frequency.

        Args:
            failed_attempts: Number of failed login attempts detected.
            time_window: Time window in seconds during which attempts occurred.

        Returns:
            Severity level string: CRITICAL, HIGH, MEDIUM, or LOW.
        """
        rate = failed_attempts / max(time_window, 1) * 60  # attempts per minute

        if rate >= 30 or failed_attempts >= 50:
            return "CRITICAL"
        elif rate >= 10 or failed_attempts >= 20:
            return "HIGH"
        elif rate >= 5 or failed_attempts >= 10:
            return "MEDIUM"
        else:
            return "LOW"


@dataclass
class AttackSession:
    """Tracks an ongoing brute-force session from a single source IP.

    Maintains a sliding window of failed authentication attempts.
    """

    source_ip: str
    attempts: list[datetime] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    log_samples: list[str] = field(default_factory=list)
    alerted: bool = False

    def add_attempt(self, timestamp: datetime, username: str, raw_line: str) -> None:
        """Record a failed authentication attempt.

        Args:
            timestamp: When the failed attempt occurred.
            username: The username that was targeted.
            raw_line: The raw log line for evidence.
        """
        self.attempts.append(timestamp)
        if username and username not in self.usernames:
            self.usernames.append(username)
        if len(self.log_samples) < 5:  # Keep max 5 samples for evidence
            self.log_samples.append(raw_line.strip())

    def prune_old_attempts(self, window_seconds: int) -> None:
        """Remove attempts outside the sliding time window.

        Args:
            window_seconds: Maximum age in seconds for attempts to be considered.
        """
        if not self.attempts:
            return
        cutoff = self.attempts[-1] - __import__("datetime").timedelta(seconds=window_seconds)
        self.attempts = [a for a in self.attempts if a >= cutoff]

    @property
    def attempt_count(self) -> int:
        """Current number of attempts in the sliding window."""
        return len(self.attempts)

    @property
    def first_seen(self) -> Optional[str]:
        """ISO timestamp of the first attempt in the window."""
        return self.attempts[0].isoformat() if self.attempts else None

    @property
    def last_seen(self) -> Optional[str]:
        """ISO timestamp of the most recent attempt."""
        return self.attempts[-1].isoformat() if self.attempts else None
