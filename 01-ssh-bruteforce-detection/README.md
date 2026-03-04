# 🔐 SSH Brute-Force Detection Engine

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE-T1110.001-red?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-17_Passing-brightgreen?style=flat-square)

*Custom intrusion detection sensor that monitors SSH authentication logs in real-time, identifies brute-force attack patterns using a sliding window algorithm, and generates structured alerts mapped to MITRE ATT&CK.*

</div>

---

## 📑 Table of Contents

- [Overview](#overview)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Lab Architecture](#-lab-architecture)
- [Attack Simulation](#️-attack-simulation)
- [Detection Logic](#️-detection-logic)
- [Installation & Usage](#-installation--usage)
- [Sample Output](#-sample-output)
- [Testing](#-testing)
- [Security+ Reference](#-comptia-security-reference)
- [Lessons Learned](#-lessons-learned)
- [References](#-references)
- [Versão em Português](#-versão-em-português)

---

## Overview

This project implements a **custom SSH brute-force detection sensor** designed to run on a Blue Team host (Ubuntu Server). The detector continuously monitors `/var/log/auth.log` for patterns of repeated failed SSH login attempts originating from the same IP address within a configurable time window.

**Key capabilities:**
- 🔍 **Real-time monitoring** — Follows auth.log live (tail -f equivalent)
- 📂 **Batch analysis** — Processes historical log files
- 🎛️ **Configurable thresholds** — Via CLI arguments or YAML config
- 📊 **SIEM-compatible output** — Structured JSON alerts with MITRE metadata
- 🔒 **Active response (IPS)** — Optional auto-block via iptables
- 🧪 **Fully tested** — 17 unit tests covering all detection logic

---

## 🎯 MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006/) |
| **Technique** | [Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/) |
| **Sub-technique** | [Password Guessing (T1110.001)](https://attack.mitre.org/techniques/T1110/001/) |
| **Data Source** | [Logon Session (DS0028)](https://attack.mitre.org/datasources/DS0028/) |
| **Platform** | Linux |
| **Detection Method** | Log analysis with sliding window + threshold |

---

## 🏗️ Lab Architecture

```
┌──────────────────────────────────────────────────────┐
│                  VirtualBox Host                      │
│                                                       │
│   ┌─────────────────┐    ┌─────────────────┐         │
│   │    Node A         │    │    Node B         │      │
│   │   RED TEAM        │    │   BLUE TEAM       │      │
│   │                   │    │                   │      │
│   │  Kali Linux       │    │  Ubuntu Server    │      │
│   │  4GB RAM / 2vCPU  │    │  2GB RAM / 1vCPU  │      │
│   │                   │    │                   │      │
│   │  Tools:           │    │  Services:        │      │
│   │  • Hydra          │───►│  • OpenSSH (22)   │      │
│   │  • Nmap           │    │  • custom_detector│      │
│   │  • Metasploit     │    │  • auth.log       │      │
│   └─────────────────┘    └─────────────────┘         │
│                                                       │
│            NAT Network: 10.0.2.0/24                   │
│          (Isolated — no external leakage)              │
└──────────────────────────────────────────────────────┘
```

| Node | Role | OS | IP (example) | Resources |
|------|------|----|--------------|-----------|
| Node A | Attacker (Red Team) | Kali Linux | 10.0.2.5 | 4GB RAM, 2 vCPUs |
| Node B | Target (Blue Team) | Ubuntu Server 22.04 | 10.0.2.10 | 2GB RAM, 1 vCPU |

### Network Setup

1. In VirtualBox: **File → Preferences → Network → NAT Networks → Add**
2. Create a NAT Network named `SOC-Lab` with CIDR `10.0.2.0/24`
3. Attach both VMs to this NAT Network
4. Verify connectivity: `ping` between nodes

---

## ⚔️ Attack Simulation

### Prerequisites (Node A — Kali)
```bash
# Verify Hydra is installed
hydra -h

# Quick port scan to confirm SSH is open on target
nmap -sV -p 22 10.0.2.10
```

### Running the Brute-Force Attack
```bash
# Basic dictionary attack against SSH
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  ssh://10.0.2.10 -t 4 -V -f

# Attack with multiple usernames
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt \
  ssh://10.0.2.10 -t 4 -V
```

> ⚠️ **Legal Notice:** Only perform these attacks in your isolated lab environment. Never test against systems without explicit authorization.

### What It Generates (Node B — Ubuntu)
The attack produces entries in `/var/log/auth.log` like:
```
Mar  3 11:00:01 ubuntu-server sshd[2001]: Failed password for root from 10.0.2.5 port 44101 ssh2
Mar  3 11:00:03 ubuntu-server sshd[2002]: Failed password for admin from 10.0.2.5 port 44102 ssh2
Mar  3 11:00:05 ubuntu-server sshd[2003]: Failed password for invalid user test from 10.0.2.5 port 44103 ssh2
```

---

## 🛡️ Detection Logic

### Algorithm: Sliding Window with Threshold

```
For each log line:
  1. Parse with regex → extract (timestamp, username, source_ip)
  2. Lookup or create AttackSession for source_ip
  3. Add attempt to session's sliding window
  4. Prune attempts older than WINDOW_SECONDS
  5. If attempt_count >= THRESHOLD and not already alerted:
       → Generate AlertEvent
       → Display / Save / Block (based on config)
```

### Regex Pattern
```python
r"(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)"
```

### Severity Classification

| Severity | Condition |
|----------|-----------|
| **CRITICAL** | ≥30 attempts/min or ≥50 total attempts |
| **HIGH** | ≥10 attempts/min or ≥20 total attempts |
| **MEDIUM** | ≥5 attempts/min or ≥10 total attempts |
| **LOW** | Below all thresholds above |

---

## 🚀 Installation & Usage

### Requirements
- Python 3.10+
- PyYAML (`pip install pyyaml`)

### Quick Start
```bash
# Clone the repository
git clone https://github.com/nicokaka/homelab-threat-detection.git
cd homelab-threat-detection/01-ssh-bruteforce-detection

# Real-time monitoring (on the Blue Team host)
sudo python3 src/custom_detector.py --log /var/log/auth.log

# Batch analysis of a log file
python3 src/custom_detector.py --log tests/sample_auth.log --batch

# Custom thresholds
python3 src/custom_detector.py --log /var/log/auth.log --threshold 10 --window 60

# Save alerts to JSON file
python3 src/custom_detector.py --log /var/log/auth.log --output alerts.json

# IPS mode — auto-block attacker IPs (requires root)
sudo python3 src/custom_detector.py --log /var/log/auth.log --auto-block

# Use YAML configuration
python3 src/custom_detector.py --config configs/detector_config.yaml
```

### CLI Options
```
usage: custom_detector [-h] [--log LOG] [--threshold THRESHOLD]
                       [--window WINDOW] [--output OUTPUT]
                       [--config CONFIG] [--auto-block] [--batch]

Options:
  --log LOG            Path to SSH auth log (default: /var/log/auth.log)
  --threshold N        Failed attempts to trigger alert (default: 5)
  --window N           Sliding window in seconds (default: 120)
  --output FILE        Save alerts as JSON
  --config FILE        YAML configuration file
  --auto-block         Auto-block IPs via iptables (IPS mode, requires root)
  --batch              Analyze entire log file (vs real-time monitoring)
```

---

## 📊 Sample Output

### Terminal Alert
```
══════════════════════════════════════════════════════════════
  🚨 BRUTE-FORCE ALERT DETECTED
══════════════════════════════════════════════════════════════
  Alert ID:      SSH-BF-90E67187
  Timestamp:     2026-03-03T21:18:00.357472+00:00
  Source IP:      192.168.10.5
  Severity:       HIGH
  Attempts:       15 in 120s
  Users Targeted: root, admin, test, guest
  MITRE:          Brute Force (T1110)
  Action:         IP logged for review
══════════════════════════════════════════════════════════════
```

### JSON Alert (SIEM-Compatible)
```json
{
  "alert_id": "SSH-BF-90E67187",
  "timestamp": "2026-03-03T21:18:00.357472+00:00",
  "severity": "HIGH",
  "source_ip": "192.168.10.5",
  "failed_attempts": 15,
  "time_window_seconds": 120,
  "first_seen": "2026-03-03T11:00:01",
  "last_seen": "2026-03-03T11:00:19",
  "usernames_targeted": ["root", "admin", "test", "guest"],
  "mitre_tactic": "Credential Access (TA0006)",
  "mitre_technique": "Brute Force (T1110)",
  "mitre_sub_technique": "Password Guessing (T1110.001)",
  "action_taken": "IP logged for review",
  "raw_log_samples": [
    "Mar  3 11:00:01 ubuntu sshd[2001]: Failed password for root from 192.168.10.5 port 44101 ssh2",
    "Mar  3 11:00:03 ubuntu sshd[2002]: Failed password for admin from 192.168.10.5 port 44102 ssh2"
  ]
}
```

---

## 🧪 Testing

```bash
# Run all tests
cd 01-ssh-bruteforce-detection
python3 -m unittest tests.test_detector -v

# Expected output: 17 tests, all passing
```

### Test Coverage

| Test Suite | Tests | What It Validates |
|-----------|-------|-------------------|
| `TestLogParsing` | 5 | Regex parsing of valid/invalid log lines |
| `TestAttackSession` | 3 | Sliding window management, username tracking |
| `TestSeverityClassification` | 4 | CRITICAL/HIGH/MEDIUM/LOW thresholds |
| `TestAlertEvent` | 2 | Alert creation and JSON serialization |
| `TestDetectorBatchAnalysis` | 3 | End-to-end detection with sample logs |

---

## 📖 CompTIA Security+ Reference

This project directly covers the following **SY0-701** exam objectives:

| Domain | Objective | Coverage |
|--------|-----------|----------|
| 4.0 Security Operations | 4.1 Given a scenario, apply common security techniques to computing resources | SSH hardening, log monitoring |
| 4.0 Security Operations | 4.4 Given a scenario, analyze indicators of malicious activity | Brute-force patterns in auth logs |
| 4.0 Security Operations | 4.9 Given a scenario, use data sources to support an investigation | auth.log analysis, JSON alerts |

---

## 💡 Lessons Learned

1. **Regex complexity** — Handling both `Failed password for <user>` and `Failed password for invalid user <user>` patterns required careful regex group design.

2. **Sliding window vs. fixed window** — A sliding window provides more accurate detection than counting attempts in fixed time blocks, as attacks can span window boundaries.

3. **IDS vs IPS trade-offs** — Auto-blocking (IPS mode) can cause denial-of-service if an attacker spoofs source IPs. In production, a secondary verification step is essential.

4. **Log timestamp parsing** — `auth.log` doesn't include year in timestamps, requiring inference from the current system date.

5. **SIEM integration** — Structuring output as JSON with consistent field names makes it trivially importable into Splunk, Elastic, or any SIEM platform.

---

## 📚 References

- [MITRE ATT&CK — T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK — T1110.001: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [CompTIA Security+ SY0-701 Exam Objectives](https://www.comptia.org/certifications/security)
- [Hydra — Network Logon Cracker](https://github.com/vanhauser-thc/thc-hydra)
- [OpenSSH Documentation](https://www.openssh.com/manual.html)

---

<details>
<summary>🇧🇷 Versão em Português</summary>

## 🔐 Motor de Detecção de Brute-Force SSH

Sensor customizado de detecção de intrusão que monitora logs de autenticação SSH em tempo real, identifica padrões de ataque de força bruta usando um algoritmo de janela deslizante, e gera alertas estruturados mapeados ao MITRE ATT&CK.

### Funcionalidades
- 🔍 **Monitoramento em tempo real** — Acompanha o auth.log ao vivo
- 📂 **Análise em lote** — Processa arquivos de log históricos
- 🎛️ **Thresholds configuráveis** — Via argumentos CLI ou config YAML
- 📊 **Saída compatível com SIEM** — Alertas JSON com metadados MITRE
- 🔒 **Resposta ativa (IPS)** — Auto-bloqueio opcional via iptables
- 🧪 **Totalmente testado** — 17 testes unitários cobrindo toda a lógica

### Como Usar
```bash
# Monitoramento em tempo real (no host Blue Team)
sudo python3 src/custom_detector.py --log /var/log/auth.log

# Análise em lote
python3 src/custom_detector.py --log tests/sample_auth.log --batch

# Thresholds customizados
python3 src/custom_detector.py --log /var/log/auth.log --threshold 10 --window 60

# Modo IPS — auto-bloquear IPs atacantes (requer root)
sudo python3 src/custom_detector.py --log /var/log/auth.log --auto-block
```

### Mapeamento MITRE ATT&CK
| Campo | Valor |
|-------|-------|
| **Tática** | Acesso a Credenciais (TA0006) |
| **Técnica** | Força Bruta (T1110) |
| **Sub-técnica** | Adivinhação de Senhas (T1110.001) |
| **Fonte de Dados** | Logs de Autenticação |
| **Plataforma** | Linux |

### Lições Aprendidas
1. **Complexidade de Regex** — Lidar com padrões `Failed password for <user>` e `Failed password for invalid user <user>` exigiu design cuidadoso dos grupos regex.
2. **Janela deslizante vs. janela fixa** — A janela deslizante fornece detecção mais precisa, pois ataques podem cruzar limites de janelas fixas.
3. **IDS vs IPS** — O auto-bloqueio pode causar negação de serviço se um atacante falsificar IPs de origem. Em produção, um segundo passo de verificação é essencial.

</details>
