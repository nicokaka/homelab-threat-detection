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
| 02 | _Log Analysis with ELK Stack_ | T1078 — Valid Accounts | ⭐⭐⭐ | 🔜 Coming Soon |
| 03 | _Malware C2 Beacon Detection_ | T1071 — Application Layer Protocol | ⭐⭐⭐⭐ | 🔜 Coming Soon |

## 🎯 Purpose

This repository serves as a **portfolio of practical cybersecurity projects** focused on:

- **Detection Engineering** — Building custom detection rules and sensors
- **Threat Hunting** — Proactively identifying attack patterns in logs
- **Incident Response** — Documenting investigation and containment procedures
- **MITRE ATT&CK Mapping** — Linking every detection to real-world adversary techniques

Each project is self-contained with its own documentation, source code, and lab setup instructions.

## 🏗️ Lab Environment

All projects run in **isolated virtual environments** using VirtualBox:

```
┌─────────────────────────────────────────────┐
│              Host Machine                    │
│                                              │
│  ┌──────────────┐    ┌──────────────┐       │
│  │   Node A      │    │   Node B      │      │
│  │  (Attacker)   │◄──►│  (Target)     │      │
│  │  Kali Linux   │    │ Ubuntu Server │      │
│  │  Hydra, Nmap  │    │   OpenSSH     │      │
│  └──────────────┘    └──────────────┘       │
│         NAT Network (Isolated)               │
└─────────────────────────────────────────────┘
```

## 🛠️ Tech Stack

- **Languages:** Python 3.10+
- **Attack Tools:** Hydra, Nmap, Metasploit
- **Defense:** Custom detection scripts, iptables
- **Virtualization:** VirtualBox (NAT Network)
- **Mapping Framework:** MITRE ATT&CK v14

## 👤 About

**Nicolas Oliveira** — IT Professional & Cybersecurity enthusiast based in Recife, Brazil.
Currently preparing for **CompTIA Security+ (SY0-701)** certification and building hands-on experience in SOC operations and detection engineering.

- 🔗 [GitHub](https://github.com/nicokaka)

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
| 02 | _Análise de Logs com ELK Stack_ | T1078 — Contas Válidas | ⭐⭐⭐ | 🔜 Em Breve |
| 03 | _Detecção de Beacon C2 de Malware_ | T1071 — Protocolo de Camada de Aplicação | ⭐⭐⭐⭐ | 🔜 Em Breve |

### 🎯 Objetivo

Este repositório é um **portfólio de projetos práticos de cibersegurança** focado em:

- **Engenharia de Detecção** — Criação de regras e sensores customizados
- **Threat Hunting** — Identificação proativa de padrões de ataque em logs
- **Resposta a Incidentes** — Documentação de investigação e contenção
- **Mapeamento MITRE ATT&CK** — Vinculando cada detecção a técnicas reais de adversários

### 🏗️ Ambiente de Laboratório

Todos os projetos rodam em **ambientes virtuais isolados** usando VirtualBox com rede NAT dedicada, garantindo que nenhum tráfego de ataque vaze para a rede externa.

### 👤 Sobre

**Nicolas Oliveira** — Profissional de TI & entusiasta de Cibersegurança em Recife, Brasil.
Preparando para a certificação **CompTIA Security+ (SY0-701)** e construindo experiência prática em operações SOC e engenharia de detecção.

</details>
