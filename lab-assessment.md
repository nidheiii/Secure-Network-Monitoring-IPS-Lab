# Lab Assessment — Summary & Lessons Learned

## Objectives Met

| Objective | Status | Evidence |
|-----------|--------|----------|
| Segmented enterprise network in GNS3 behind FortiGate/pfSense | Complete | `topology/network-design.md` |
| Suricata IPS deployed with custom recon + auth rules | Complete | `ips-suricata/custom-rules.rules` |
| Firewall + IPS events centralized in Wazuh via Syslog | Complete | `siem-wazuh/syslog-forwarding.md`, `ossec.conf` |
| Nmap reconnaissance simulated and measured | Complete | `attack-simulation/nmap-scenarios.md` |
| Hydra brute force simulated and measured | Complete | `attack-simulation/hydra-scenarios.md` |
| Alerting workflows by severity and source | Complete | `siem-wazuh/alerting-workflows.md` |
| Suricata and Wazuh rules tuned to reduce FPs | Complete | `ips-suricata/rule-tuning.md` |
| Firewall policies, ACLs, AAA controls documented | Complete | `perimeter-firewall/`, `hardening/` |
| Incident-response runbook written | Complete | `runbook/incident-response-runbook.md` |

## Key Findings

### Detection Performance
- All Nmap scan types (SYN, connect, NULL, FIN, XMAS, UDP, OS fingerprint, service probe) detected by Suricata custom rules → Wazuh rule 200001.
- All Hydra brute force services (SSH, RDP, HTTP, SMB, FTP) detected → Suricata sid 1000101-1000107, Wazuh rules 100101 / 200002.
- Detection delay typically under 60 seconds for threshold-based rules.
- Firewall deny logs correlated with IPS alerts for full attack chain visibility.

### Tuning Outcomes
- Baseline (24h no attack) false positives identified from Wazuh management traffic and Windows update traffic.
- Suppressions added for Wazuh server IP (10.0.99.20) on recon rules.
- Thresholds adjusted: SSH brute force 5 failures/60s to match account lockout policy.
- Post-tuning: true positives still fire, false positives eliminated.

### Hardening Gaps Closed
- Default deny perimeter policy with catch-all logging.
- Management plane restricted to Mgmt VLAN.
- RADIUS AAA with local fallback and lockout.
- Inter-VLAN ACLs prevent lateral movement (Users cannot reach Servers directly).
- SSH key-based auth / `PermitRootLogin no` on targets.

## Recommendations / Next Steps

1. **Deploy MFA** for all administrative access (FortiGate/pfSense + SSH).
2. **Enable Suricata IPS drop mode** (currently IDS baseline) after final tuning validation.
3. **Integrate Wazuh with email/Slack** for Critical/High alerts (integration block in `ossec.conf`).
4. **Add active response** in Wazuh (auto-block source IP at firewall via API/CLI on brute force).
5. **Expand detection** to cover lateral movement (SMB/RDP internal scanning), data exfiltration, and DNS tunneling.
6. **Quarterly review** of firewall rules, admin accounts, and Suricata suppressions.
7. **Automate metrics collection** with scripts that parse `eve.json` and `alerts.log` into a detection dashboard.

## MITRE ATT&CK Coverage

| Technique | ID | Detected By |
|-----------|-----|-------------|
| Network Service Scanning | T1046 | Suricata custom rules + Wazuh 200001 |
| Brute Force | T1110 | Suricata custom rules + Wazuh 100101 / 200002 |
| Valid Accounts (attempted) | T1078 | Wazuh 100101, 100102 |
| OS Credential Dumping (prep) | T1003 | Monitor via Syslog/eve.json (future) |

## Files to Preserve for Audit

- `perimeter-firewall/fortigate-cli-config.conf` (or pfSense notes)
- `ips-suricata/suricata.yaml` + `custom-rules.rules`
- `siem-wazuh/ossec.conf` + `local-rules.xml`
- `attack-simulation/results/` (raw scan/attack output)
- `runbook/incident-response-runbook.md`
- `lab-assessment.md` (this file)
