<div align="center">

# 🛡️ Homelab Threat Detection

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=for-the-badge)
![Security](https://img.shields.io/badge/CompTIA_Security+-Study_Projects-orange?style=for-the-badge)

**A hands-on collection of detection engineering projects built in isolated virtual environments.**
**Each module simulates real-world attack scenarios mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework.**

---

</div>

## 📋 Projects

| # | Project | ATT&CK Technique | Difficulty | Status |
|---|---------|-------------------|------------|--------|
| 01 | [SSH Brute-Force Detection Engine](./01-ssh-bruteforce-detection/) | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) | ⭐⭐ | ✅ Complete |
| 02 | _Port Scan Detection & SIEM Integration_ | [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/) | ⭐⭐⭐ | 🔜 Coming Soon |
| 03 | _Web Attack Detection (SQLi/XSS)_ | [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | ⭐⭐⭐ | 🔜 Coming Soon |
| 04 | _Detection Rule Tuning & False Positive Reduction_ | — | ⭐⭐⭐⭐ | 🔜 Coming Soon |
| 05 | _End-to-End Incident Investigation Report_ | Multiple | ⭐⭐⭐⭐ | 🔜 Coming Soon |

## 📊 Key Results

- 🔍 **100% detection rate** on SSH brute-force attacks (Hydra, 500+ login attempts)
- ⏱️ **Real-time auto-blocking** — Malicious IPs banned via iptables within seconds of detection
- 🗺️ **MITRE ATT&CK mapped** — Every detection linked to real-world adversary techniques
- 🐍 **Custom-built tooling** — Detection engine written from scratch in Python (no off-the-shelf tools)

## 🎯 Purpose

This repository serves as a **portfolio of practical cybersecurity projects** focused on:

- **Detection Engineering** — Building custom detection rules and sensors
- **Threat Hunting** — Proactively identifying attack patterns in logs
- **Incident Response** — Documenting investigation and containment procedures
- **MITRE ATT&CK Mapping** — Linking every detection to real-world adversary techniques

Each project is self-contained with its own documentation, source code, and lab setup instructions.

## 🏗️ Lab Architecture

All projects run in **isolated virtual environments** using VirtualBox:

┌───────────────────────────────────────────────────┐
│                  Host Machine                     │
│                                                   │
│   ┌──────────────┐          ┌──────────────┐      │
│   │   Attacker   │          │    Target    │      │
│   │  Kali Linux  │ ◄──────► │ Ubuntu Server│      │
│   │  Hydra, Nmap │          │   OpenSSH    │      │
│   └──────────────┘          └──────────────┘      │
│                                                   |
│              NAT Network (Isolated)               | 
└───────────────────────────────────────────────────┘


> ⚠️ All attack traffic is confined to an isolated NAT network — no traffic reaches external networks.

## 🛠️ Tech Stack

| Category | Tools |
|----------|-------|
| **Languages** | Python 3.10+ |
| **Attack Simulation** | Hydra, Nmap, Metasploit |
| **Defense & Detection** | Custom Python scripts, iptables, Sigma rules |
| **SIEM** | ELK Stack / Wazuh _(upcoming)_ |
| **Virtualization** | VirtualBox (NAT Network) |
| **Framework** | MITRE ATT&CK v14 |

## 👤 About

**Nicolas Oliveira** — IT Professional with **5 years of experience** managing **300+ endpoints** (MDM, EDR, ZTNA) in enterprise environments. Currently preparing for **CompTIA Security+ (SY0-701)** and building hands-on skills in Detection Engineering and SOC Operations.

- 🔗 [GitHub](https://github.com/nicokaka)
- 💼 [LinkedIn](https://linkedin.com/in/seu-linkedin)

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<details>
<summary>🇧🇷 Versão em Português</summary>

## 🛡️ Homelab Threat Detection

**Uma coleção prática de projetos de engenharia de detecção construídos em ambientes virtuais isolados.**
**Cada módulo simula cenários de ataque reais mapeados ao framework [MITRE ATT&CK](https://attack.mitre.org/).**

### 📋 Projetos

| # | Projeto | Técnica ATT&CK | Dificuldade | Status |
|---|---------|-----------------|-------------|--------|
| 01 | [Motor de Detecção SSH Brute-Force](./01-ssh-bruteforce-detection/) | [T1110 — Força Bruta](https://attack.mitre.org/techniques/T1110/) | ⭐⭐ | ✅ Completo |
| 02 | _Detecção de Port Scan & Integração SIEM_ | [T1046 — Descoberta de Serviços de Rede](https://attack.mitre.org/techniques/T1046/) | ⭐⭐⭐ | 🔜 Em Breve |
| 03 | _Detecção de Ataques Web (SQLi/XSS)_ | [T1190 — Exploração de Aplicação Pública](https://attack.mitre.org/techniques/T1190/) | ⭐⭐⭐ | 🔜 Em Breve |
| 04 | _Tuning de Regras & Redução de Falsos Positivos_ | — | ⭐⭐⭐⭐ | 🔜 Em Breve |
| 05 | _Relatório de Investigação de Incidente End-to-End_ | Múltiplos | ⭐⭐⭐⭐ | 🔜 Em Breve |

### 📊 Resultados Principais

- 🔍 **100% de taxa de detecção** em ataques SSH brute-force (Hydra, 500+ tentativas)
- ⏱️ **Bloqueio automático em tempo real** — IPs maliciosos banidos via iptables em segundos
- 🗺️ **Mapeado ao MITRE ATT&CK** — Cada detecção vinculada a técnicas reais de adversários
- 🐍 **Ferramentas customizadas** — Motor de detecção escrito do zero em Python

### 🎯 Objetivo

Este repositório é um **portfólio de projetos práticos de cibersegurança** focado em:

- **Engenharia de Detecção** — Criação de regras e sensores customizados
- **Threat Hunting** — Identificação proativa de padrões de ataque em logs
- **Resposta a Incidentes** — Documentação de investigação e contenção
- **Mapeamento MITRE ATT&CK** — Vinculando cada detecção a técnicas reais de adversários

### 🏗️ Ambiente de Laboratório

Todos os projetos rodam em **ambientes virtuais isolados** usando VirtualBox com rede NAT dedicada, garantindo que nenhum tráfego de ataque vaze para a rede externa.

### 👤 Sobre

**Nicolas Oliveira** — Profissional de TI com **5 anos de experiência** gerenciando **300+ endpoints** (MDM, EDR, ZTNA) em ambientes corporativos. Preparando para a certificação **CompTIA Security+ (SY0-701)** e construindo experiência prática em Engenharia de Detecção e Operações SOC.

</details>
