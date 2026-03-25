import socket
import csv
import time
from scapy.all import *
import os

TARGET_IP = "192.168.56.20"
CSV_DB = "standalone_siem.csv"

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
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = str(packet[Raw].load).lower()
        # Look for Metasploit/Java-RMI exploit signatures
        if "java" in payload or "rmi" in payload:
            src_ip = packet[IP].src
            msg = "EXPLOIT IN PROGRESS"
            print(f"[!!!] {msg} from {src_ip} - Status: CRITICAL")
            with open(CSV_DB, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), src_ip, "CRITICAL", "Suspicious Java RMI Payload Detected"])

if __name__ == "__main__":
    init_db()
    check_java_vuln()
    print("[*] Sniffing Phase: Waiting for Attack on port 1099...")
    sniff(filter="tcp port 1099", prn=detect_attack, store=0)
