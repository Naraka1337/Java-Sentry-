# Standalone Cyber Sentinel 🛡️

A standalone Intrusion Detection System (IDS) and Scanner built with Python. This tool demonstrates proactive scanning and deep packet inspection to secure a network.

## Features

- **Proactive Scanning:** Automatically checks the target IP on port 1099 to identify a vulnerable Java RMI banner before any attack occurs.
- **Deep Packet Inspection (Sniffing):** Monitors network traffic in real-time, specifically checking packets destined for the target port for signatures indicating exploitation attempts (like 'java' or 'rmi' payloads typical in Metasploit attacks).
- **Incident Logging:** Logs all findings to a CSV database instantly.
- **Live Interactive Dashboard:** Includes a Streamlit UI that updates every second to display the status (`MONITORING`, `RISK`, or `CRITICAL`) and logs.

## Setup & Dependencies

```bash
pip install scapy pandas streamlit
```

## How to use

Run the two scripts in separate terminals:

1. **Start the Scanner & Live Sniffer**
   ```bash
   python sentinel_logic.py
   ```

2. **Start the Streamlit Monitoring Dashboard**
   ```bash
   streamlit run app.py
   ```

## Workflow Example
1. The `sentinel_logic.py` script starts scanning. If it detects an open and responsive Java RMI Registry, the dashboard changes state to report a `RISK`.
2. As the script silently monitors the network layer, if an incoming payload from Metasploit is detected matching the rules, it immediately logs a `CRITICAL` breach.
3. The Streamlit dashboard updates automatically and sounds the alarm visually.

## Disclaimer
This tool is built for educational and defensive purposes to be tested against intentionally vulnerable machines like Metasploitable.
