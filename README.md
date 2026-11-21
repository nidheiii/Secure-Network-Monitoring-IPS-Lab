# Secure Network Monitoring & IPS Lab — Real-Time Defense Platform

A complete, enterprise-grade network security lab and real-time defense simulation platform demonstrating perimeter defense, intrusion detection/prevention, centralized SIEM logging, attack simulation, alert tuning, automated quarantine, and incident response.

![Platform](https://img.shields.io/badge/Status-Real--Time%20Working-emerald?style=flat-square)
![Detection Rate](https://img.shields.io/badge/Detection%20Rate-100%25-brightgreen?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1046%20%7C%20T1110%20%7C%20T1078-blue?style=flat-square)
![Architecture](https://img.shields.io/badge/Architecture-FortiGate%20%7C%20Suricata%20%7C%20Wazuh-blueviolet?style=flat-square)

---

## Live Working Real-Time Platform

The repository contains both the **enterprise architectural configurations** (GNS3, FortiGate, Suricata, Wazuh) and a **fully working real-time application** featuring:

1. **Interactive SOC Web Console (`http://localhost:8000`)**:
   - **Real-Time SVG Topology Canvas**: Live packet flow across WAN, FortiGate Perimeter Firewall, Inline Suricata IPS sensor, Core Switch, DMZ (VLAN 10), Users (VLAN 20), Servers (VLAN 30), and Mgmt (VLAN 99).
   - **Live Alert Triage & SIEM Feed**: Color-coded alerts with MITRE ATT&CK tags (`T1046`, `T1110`, `T1078`), Wazuh rule IDs, severity levels (Critical, High, Medium, Low), and packet inspection modals.
   - **Attack Simulation Deck**: 1-click execution for all 10 Nmap reconnaissance scenarios and 6 Hydra brute-force scenarios with live Kali terminal output.
   - **Enforcement Mode Switch**: Toggle seamlessly between **IDS (Passive Alerting)** and **IPS (Inline Packet Dropping)**.
   - **Active Response & Perimeter Quarantine**: Real-time IP blacklist with automated threat quarantine and manual unblock controls.
   - **Interactive Incident Response Runbook**: Built-in 4-phase incident workflow with 1-click attacker containment and exportable Markdown incident reports.

2. **Core Security Engines (`core/`)**:
   - `core/firewall.py`: Stateful perimeter firewall engine with zone-based ACLs, connection tracking, and dynamic quarantine.
   - `core/suricata_ips.py`: Real-time Suricata IPS engine parsing and enforcing `ips-suricata/custom-rules.rules`, sliding-window threshold tracking, and writing authentic `logs/fast.log` and `logs/eve.json`.
   - `core/wazuh_siem.py`: Wazuh SIEM correlator processing `siem-wazuh/local-rules.xml`, syslog parsing, MITRE mapping, and automated active-response quarantine.
   - `core/attack_simulator.py`: Attack generator for Nmap, Hydra, and benign enterprise background traffic.
   - `core/syslog_server.py`: Asynchronous UDP Syslog server on port 5140 receiving RFC 3164/5424 logs.
   - `core/metrics.py`: Computes live detection rate (%), detection delay (s), false positive rate (%), and MITRE coverage.

---

## Quick Start

### 1. Launch the Real-Time SOC Dashboard (Recommended)

```bash
python run_lab.py
```

This launches the backend server, UDP syslog daemon, starts normal enterprise background traffic, and automatically opens the interactive SOC Console at `http://localhost:8000`.

### 2. Run the Automated CLI Benchmark Suite

To execute all 10 Nmap scenarios and 5 Hydra brute-force scenarios in sequence, measure performance, and generate a markdown metrics report:

```bash
python simulate_cli.py
```

### 3. Run Automated Unit & Integration Tests

```bash
python tests/test_core.py
```

---

## 📊 Measured Benchmark Performance

Tested and verified via `simulate_cli.py` (see [attack-simulation/detection-metrics-live.md](attack-simulation/detection-metrics-live.md)):

| Metric | Target | Measured Result | Status |
|--------|--------|-----------------|--------|
| **Reconnaissance Detection Rate (Nmap)** | 90%+ | **10 / 10 (100.0%)** |  PASS |
| **Brute Force Detection Rate (Hydra)** | 90%+ | **5 / 5 (100.0%)** |  PASS |
| **Max Detection Delay** | <60s | **<1.24s (Avg 0.51s)** |  PASS |
| **False Positive Rate (Baseline)** | <5% | **0.0%** |  PASS |
| **MITRE ATT&CK Coverage** | Complete | **100% (T1046, T1110, T1078)** |  PASS |
| **Inline IPS Packet Drop** | Verified | **Active & Enforced** |  PASS |

---

##  Project Directory Structure

```
secure-network-monitoring-ips-lab/
├── README.md                           # Project documentation & quick start
├── run_lab.py                          # 1-Click launcher (Web SOC + Server)
├── server.py                           # FastAPI + WebSockets real-time server
├── simulate_cli.py                     # Automated CLI benchmark runner
│
├── core/                               # Core Python Security Engines
│   ├── models.py                       # Packets, alerts, quarantine & rule schemas
│   ├── firewall.py                     # Stateful perimeter firewall & quarantine
│   ├── suricata_ips.py                 # Suricata IPS engine & rule compiler
│   ├── wazuh_siem.py                   # Wazuh SIEM correlator & active response
│   ├── attack_simulator.py             # Nmap, Hydra & normal traffic generator
│   ├── syslog_server.py                # Asynchronous UDP Syslog listener (port 5140)
│   ├── metrics.py                      # Live telemetry & KPI calculator
│   └── engine.py                       # Central lab orchestrator
│
├── web/                                # Modern Cyber SOC Console
│   ├── index.html                      # HTML5 responsive SOC dashboard
│   ├── style.css                       # Cybersecurity dark-mode theme
│   └── app.js                          # WebSocket client & SVG topology animation
│
├── logs/                               # Authentic Generated Security Logs
│   ├── fast.log                        # Suricata fast alerts log
│   ├── eve.json                        # Suricata EVE JSON event stream
│   ├── wazuh-alerts.json               # Wazuh SIEM alerts JSON format
│   └── wazuh-alerts.log                # Standard Wazuh alert log
│
├── tests/                              # Automated Test Suite
│   └── test_core.py                    # Unit tests for firewall, IPS, SIEM, & simulator
│
├── topology/                           # Enterprise GNS3 Network Architecture
│   ├── network-design.md               # Logical design, VLANs, IP addressing
│   └── gns3-topology.drawio            # Topology diagram source
│
├── perimeter-firewall/                 # FortiGate / pfSense Configuration
│   ├── fortigate-cli-config.conf       # FortiGate CLI commands
│   ├── pfsense-config-notes.md         # pfSense GUI/CLI notes
│   ├── firewall-policies.md            # Security policies, ACLs, NAT rules
│   └── aaa-controls.md                 # AAA authentication controls
│
├── ips-suricata/                       # Suricata Configuration & Rules
│   ├── suricata.yaml                   # Suricata main configuration
│   ├── custom-rules.rules              # 17 Custom rules (Recon + Brute force)
│   ├── rule-tuning.md                  # Tuning & suppression documentation
│   └── ips-logging.md                  # Eve.json & fast.log setup
│
├── siem-wazuh/                         # Wazuh SIEM Configuration
│   ├── ossec.conf                      # Wazuh manager configuration
│   ├── local-rules.xml                 # Custom Wazuh detection rules & MITRE tags
│   ├── syslog-forwarding.md            # Syslog transport documentation
│   └── alerting-workflows.md           # Alert triage workflows
│
├── attack-simulation/                  # Attack Scenarios & Detection Metrics
│   ├── nmap-scenarios.md               # 10 Nmap scan scenarios
│   ├── hydra-scenarios.md              # 6 Hydra brute-force scenarios
│   ├── detection-metrics.md            # Measurement methodology & template
│   └── detection-metrics-live.md       # Live benchmark run results
│
├── runbook/                            # Incident Response
│   └── incident-response-runbook.md    # 4-Phase investigation workflow
│
└── hardening/                          # Perimeter & Host Hardening
    └── hardening-guide.md              # Firewall, host, SSH, and AAA hardening
```

---

##  Supported Attack Scenarios

### Reconnaissance (Nmap)
1. **Scenario 1**: SYN Stealth Scan (`-sS -T4 -p-`) → SID 1000001 (Wazuh 200001, MITRE T1046)
2. **Scenario 2**: TCP Connect Scan (`-sT -T4 -p-`) → SID 1000002 (Wazuh 200001, MITRE T1046)
3. **Scenario 3A**: TCP NULL Scan (`-sN`) → SID 1000003
4. **Scenario 3B**: TCP FIN Scan (`-sF`) → SID 1000004
5. **Scenario 3C**: TCP XMAS Scan (`-sX`) → SID 1000005
6. **Scenario 3D**: TCP ACK Scan (`-sA`) → SID 1000006
7. **Scenario 4**: UDP Scan (`-sU`) → SID 1000007
8. **Scenario 5**: Service Version Probe (`-sV`) → SID 1000010
9. **Scenario 6**: OS Detection Fingerprint (`-O`) → SID 1000009
10. **Scenario 7**: Broad Port Sweep (35+ ports) → SID 1000008

### Authentication Brute Force (Hydra)
1. **Scenario 1**: SSH Brute Force → SID 1000101 (Wazuh 200002 & 100101, MITRE T1110)
2. **Scenario 3**: HTTP POST Form Brute Force (`/login`) → SID 1000103
3. **Scenario 4**: RDP Brute Force (`TCP 3389`) → SID 1000102
4. **Scenario 5**: SMB Brute Force (`TCP 445`) → SID 1000106
5. **Scenario 6**: FTP Brute Force (`TCP 21`) → SID 1000107

---

## Incident Response Runbook Integration

The platform provides a guided 4-phase incident response cycle:
1. **Phase 1: Detection & Triage**: Automatic classification into Critical, High, Medium, and Low severity.
2. **Phase 2: Deep Forensics**: Inspect raw packet payloads, TCP flags, TTL values, and log traces.
3. **Phase 3: Automated Containment**: 1-Click host isolation and perimeter firewall blacklisting.
4. **Phase 4: Reporting**: 1-Click generation and export of Markdown Incident Reports.

---

## Safety & Ethics

This lab is strictly intended for **authorized, controlled, educational, and simulation use**. All synthetic traffic and attacks run locally within the isolated lab environment.
