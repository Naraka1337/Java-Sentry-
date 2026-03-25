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
    # Only process TCP packets on port 1099
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].dport == 1099 or packet[TCP].sport == 1099:
            # Debug: Print any packet to/from 1099
            print(f"[DEBUG] Intercepted TCP Packet: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")
            
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                payload_str = str(raw_data).lower()
                
                # Look for Metasploit/Java-RMI exploit signatures or Java Magic Bytes
                if b"\xac\xed" in raw_data or "java" in payload_str or "rmi" in payload_str:
                    src_ip = packet[IP].src
                    msg = "EXPLOIT IN PROGRESS"
                    print(f"[!!!] {msg} from {src_ip} - Status: CRITICAL")
                    with open(CSV_DB, "a", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), src_ip, "CRITICAL", "Suspicious Java RMI Payload Detected"])

if __name__ == "__main__":
    init_db()
    check_java_vuln()
    print("[*] Sniffing Phase: Waiting for Attack on port 1099... (Listening on ALL interfaces)")
    # Using iface="any" and filtering in Python to bypass any OS pcap issues
    sniff(prn=detect_attack, store=0, iface="any")
