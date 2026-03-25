import socket
import csv
import time
import re
from scapy.all import *
import os

TARGET_IP = "192.168.56.20"
CSV_DB = "standalone_siem.csv"
DEBUG_MODE = False
ALERT_COOLDOWN = 10
last_alert_time = {}

# Common shell commands or tools used in payloads
SUSPICIOUS_CMDS = [b"bash", b"sh", b"cmd.exe", b"powershell", b"wget", b"curl", b"nc ", b"netcat", b"python"]

def init_db():
    if not os.path.exists(CSV_DB):
        with open(CSV_DB, 'w', newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Source IP", "Status", "Message", "Extracted Payload"])
    else:
        # Check if the existing CSV has the new column structure
        with open(CSV_DB, 'r') as f:
            first_line = f.readline()
        if "Extracted Payload" not in first_line:
            os.remove(CSV_DB)
            with open(CSV_DB, 'w', newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Source IP", "Status", "Message", "Extracted Payload"])

def extract_commands(raw_data):
    # Extract all printable ASCII strings of length >= 4
    strings = re.findall(b"[\x20-\x7E]{4,}", raw_data)
    extracted = []
    
    for s in strings:
        s_lower = s.lower()
        if any(cmd in s_lower for cmd in SUSPICIOUS_CMDS) or b"/" in s or b"\\" in s:
            try:
                decoded = s.decode('utf-8', errors='ignore').strip()
                if decoded and len(decoded) > 3:
                    extracted.append(decoded)
            except:
                pass
                
    if extracted:
        # Filter out duplicates and keep top 3 commands
        unique_cmds = list(dict.fromkeys(extracted))
        return " | ".join(unique_cmds[:3])
    
    if strings:
        longest = max(strings, key=len)
        try:
            return longest.decode('utf-8', errors='ignore')[:50]
        except:
            return "Binary/Encrypted Data"
            
    return "Undetectable payload"

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
                writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), "Scanner (Local)", "RISK", msg, "N/A"])
            s.close()
            return True
        else:
            raise Exception("Port Closed")
    except Exception as e:
        print(f"[-] Target Port 1099 is Closed. Status: SAFE")
        with open(CSV_DB, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), "Scanner (Local)", "SAFE", "No Vulnerability Detected", "N/A"])
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
                
                payload_details = extract_commands(raw_data)
                
                if src_ip not in last_alert_time or (current_time - last_alert_time[src_ip]) > ALERT_COOLDOWN:
                    last_alert_time[src_ip] = current_time
                    msg = "EXPLOIT IN PROGRESS"
                    print(f"\n[!!!] 🚨 {msg} from {src_ip} - Status: CRITICAL")
                    print(f"      ↳ Payload Snippet: {payload_details}")
                    with open(CSV_DB, "a", newline="") as f:
                        writer = csv.writer(f)
                        writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), src_ip, "CRITICAL", "Suspicious Java RMI Payload Detected", payload_details])

if __name__ == "__main__":
    init_db()
    check_java_vuln()
    print("[*] Sniffing Phase: Waiting for Attack on port 1099... (Listening on ens33)")
    sniff(prn=detect_attack, store=0, iface="ens33")
