import socket
import csv
import time
from scapy.all import *
import os

TARGET_IP = "192.168.56.20"
CSV_DB = "standalone_siem.csv"
DEBUG_MODE = False  # Toggle this to True if you need to see all packets again
ALERT_COOLDOWN = 10  # Seconds to wait before alerting for the same IP again
last_alert_time = {}

def init_db():
    # Initialize the log file with headers if it doesn't exist
    with open(CSV_DB, 'w', newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Source IP", "Status", "Message"])

def check_java_vuln():
    print(f"[*] Scanning Phase: Checking {TARGET_IP}:1099 for Java RMI Vulnerability...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((TARGET_IP, 1099))
        
        if result == 0:
            msg = "VULNERABILITY DETECTED (Java RMI Registry Open)"
            print(f"[!] {msg} - Status: RISK")
            with open(CSV_DB, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), "Scanner (Local)", "RISK", msg])
            s.close()
            return True
        else:
            raise Exception("Port Closed")
    except Exception as e:
        print(f"[-] Target Port 1099 is Closed. Status: SAFE")
        with open(CSV_DB, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), "Scanner (Local)", "SAFE", "No Vulnerability Detected"])
        return False

def detect_attack(packet):
    # Only process TCP packets directed TO port 1099 (Attacker -> Server)
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].dport == 1099:
        if DEBUG_MODE:
            print(f"[DEBUG] Intercepted TCP Packet: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
            
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            payload_str = str(raw_data).lower()
            
            # Look for Metasploit/Java-RMI exploit signatures or Java Magic Bytes
            if b"\xac\xed" in raw_data or "java" in payload_str or "rmi" in payload_str:
                src_ip = packet[IP].src
                current_time = time.time()
                
                # Check cooldown to prevent log spamming from a single attack stream
                if src_ip not in last_alert_time or (current_time - last_alert_time[src_ip]) > ALERT_COOLDOWN:
                    last_alert_time[src_ip] = current_time
                    msg = "EXPLOIT IN PROGRESS"
                    print(f"\n[!!!] 🚨 {msg} from {src_ip} - Status: CRITICAL")
                    with open(CSV_DB, "a", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), src_ip, "CRITICAL", "Suspicious Java RMI Payload Detected"])

if __name__ == "__main__":
    init_db()
    check_java_vuln()
    print("[*] Sniffing Phase: Waiting for Attack on port 1099... (Listening on ens33)")
    # Explicitly using ens33 since it is the interface connected to the 192.168.56.0/24 subnet
    sniff(prn=detect_attack, store=0, iface="ens33")
