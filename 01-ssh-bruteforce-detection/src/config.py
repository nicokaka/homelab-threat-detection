"""
config.py — Default configuration and constants for the SSH brute-force detector.

All values can be overridden via CLI arguments or YAML configuration file.
"""

# ──────────────────────────────────────────────
# Detection Thresholds
# ──────────────────────────────────────────────

# Number of failed attempts from the same IP to trigger an alert
DEFAULT_THRESHOLD: int = 5

# Sliding time window (in seconds) to count failed attempts
DEFAULT_WINDOW_SECONDS: int = 120

# ──────────────────────────────────────────────
# Log Parsing
# ──────────────────────────────────────────────

# Default path to the SSH authentication log
DEFAULT_LOG_PATH: str = "/var/log/auth.log"

# Regex pattern to match failed SSH authentication attempts
# Captures: month, day, time, hostname, source_ip, optional username
AUTH_FAIL_PATTERN: str = (
    r"(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
    r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)"
)

# ──────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────

# Default output file for alerts (None = stdout only)
DEFAULT_OUTPUT_FILE: str | None = None

# ──────────────────────────────────────────────
# Active Response (IPS Mode)
# ──────────────────────────────────────────────

# iptables command template for auto-blocking an attacker IP
IPTABLES_BLOCK_CMD: str = "iptables -A INPUT -s {ip} -j DROP"

# ──────────────────────────────────────────────
# Display
# ──────────────────────────────────────────────

# ANSI color codes for terminal output
COLORS: dict[str, str] = {
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "GREEN": "\033[92m",
    "CYAN": "\033[96m",
    "BOLD": "\033[1m",
    "RESET": "\033[0m",
}

# Banner displayed on startup
BANNER: str = r"""
╔══════════════════════════════════════════════════════════════╗
║       🛡️  SSH Brute-Force Detection Engine v1.0.0           ║
║       MITRE ATT&CK: T1110.001 — Password Guessing          ║
╚══════════════════════════════════════════════════════════════╝
"""
