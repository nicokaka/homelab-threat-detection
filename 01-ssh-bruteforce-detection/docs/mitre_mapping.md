# MITRE ATT&CK Mapping — SSH Brute-Force Detection

## Technique Overview

| Field | Value |
|-------|-------|
| **ID** | T1110.001 |
| **Name** | Brute Force: Password Guessing |
| **Tactic** | Credential Access (TA0006) |
| **Platform** | Linux, macOS, Windows |
| **Data Source** | Application Log (DS0015), Logon Session (DS0028) |
| **Permissions Required** | None (external attack) |
| **Version** | 1.4 |

## Description

Adversaries with no prior knowledge of legitimate credentials within the
system may systematically guess passwords using a repetitive or iterative
mechanism. Password guessing may or may not take into account the target's
password policy considerations.

## Detection Data Sources

| Data Source | Component | How We Detect |
|-------------|-----------|---------------|
| Application Log | Content | Parse `sshd` entries in `/var/log/auth.log` |
| Logon Session | Creation | Track failed `Failed password for` events |
| Logon Session | Metadata | Extract source IP, username, timestamp |

## Detection Rule Logic

```
RULE: SSH Brute-Force Detection
WHEN:
  - Source: /var/log/auth.log
  - Pattern: "Failed password for" (sshd)
  - Count(source_ip) >= THRESHOLD within WINDOW_SECONDS
THEN:
  - Generate AlertEvent with MITRE metadata
  - Severity = f(attempt_rate, total_count)
  - Optional: iptables DROP rule on source_ip
```

## MITRE ATT&CK Navigator Layer

This detection covers the following cells in the ATT&CK Navigator:

```
Tactic:     TA0006 (Credential Access)
└── T1110   Brute Force
    ├── T1110.001  Password Guessing     ← COVERED
    ├── T1110.002  Password Cracking
    ├── T1110.003  Password Spraying
    └── T1110.004  Credential Stuffing
```

## References

- https://attack.mitre.org/techniques/T1110/001/
- https://attack.mitre.org/tactics/TA0006/
- https://attack.mitre.org/datasources/DS0028/
