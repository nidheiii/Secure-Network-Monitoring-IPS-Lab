"""
One-Click Launcher for Secure Network Monitoring & IPS Lab
Starts the real-time backend engine, UDP syslog daemon, and launches the SOC web dashboard.
"""

import os
import sys
import webbrowser
import threading
import time
import uvicorn


def open_browser_delayed(url: str, delay: float = 1.2):
    time.sleep(delay)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def print_banner():
    banner = r"""
  =============================================================================
    SECURE NETWORK MONITORING & IPS LAB - REAL-TIME DEFENSE PLATFORM
  =============================================================================
    Components Active:
      [✓] Perimeter Firewall : FortiGate / pfSense Stateful ACL & NAT Engine
      [✓] Intrusion Defense  : Suricata IPS Engine (custom-rules.rules compiled)
      [✓] Centralized SIEM   : Wazuh Correlator (local-rules.xml + MITRE ATT&CK)
      [✓] Attack Simulator   : Kali Linux Nmap & Hydra Scenario Generator
      [✓] Active Response    : Automated IP Quarantine & Containment
      [✓] Syslog Daemon      : UDP 5140 (RFC 3164/5424 Receiver)
      [✓] Web SOC Console    : http://localhost:8000
  =============================================================================
    Press Ctrl+C to stop the platform anytime.
  =============================================================================
    """
    print(banner)


def main():
    print_banner()

    # Launch browser in a background thread
    threading.Thread(target=open_browser_delayed, args=("http://localhost:8000", 1.5), daemon=True).start()

    # Start Uvicorn ASGI server
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False, log_level="info")


if __name__ == "__main__":
    main()
