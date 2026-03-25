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
        s.settimeout(2)
        s.connect((TARGET_IP, 1099))
        banner = s.recv(1024)
        s.close()
        
        # If open and responds, log the risk
        msg = "VULNERABILITY DETECTED (CVE-2013-4040 / Java RMI)"
        print(f"[!] {msg} - Status: RISK")
        
        with open(CSV_DB, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), "Scanner (Local)", "RISK", msg])
        return True
    except Exception as e:
        print(f"[-] Target is secured or offline. Status: SAFE")
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
    sniff(filter=f"ip dst {TARGET_IP} and tcp port 1099", prn=detect_attack, store=0)
