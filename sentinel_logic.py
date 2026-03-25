import socket
import csv
import time
from scapy.all import *

TARGET_IP = "192.168.56.20" # The target Metasploitable IP
CSV_DB = "standalone_siem.csv"

# 1. Vulnerability Check before attack
def check_java_vuln():
    print(f"🔍 Scanning {TARGET_IP} for Java RMI Vulnerability...")
    try:
        # Try to open port 1099 and read the first two words
        s = socket.socket()
        s.settimeout(2)
        s.connect((TARGET_IP, 1099))
        banner = s.recv(1024)
        s.close()
        # If the port is open and responds, this is a danger sign in Metasploitable
        return True, "Java RMI Registry is OPEN (Vulnerable Version Detected)"
    except:
        return False, "Safe"

# 2. Live Network IDS monitoring
def detect_attack(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = str(packet[Raw].load)
        # Metasploit fingerprint in Java RMI attacks
        if "java" in payload.lower() or "rmi" in payload.lower():
            timestamp = time.strftime("%H:%M:%S")
            print(f"🚨 [ALERT] Exploit Payload Detected from {packet[IP].src}!")
            with open(CSV_DB, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, packet[IP].src, "CRITICAL", "Java RCE Exploit Detected"])

if __name__ == "__main__":
    # Initialize the log file
    with open(CSV_DB, 'w', newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "Source", "Level", "Details"])

    # Step 1: Scan
    is_vuln, msg = check_java_vuln()
    if is_vuln:
        with open(CSV_DB, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([time.strftime("%H:%M:%S"), "Scanner", "RISK", msg])

    # Step 2: Network Sniffing
    print("🛡️ Sentinel is Sniffing for attacks... (Waiting for Metasploit)")
    sniff(filter=f"ip dst {TARGET_IP} and tcp port 1099", prn=detect_attack, store=0)
