"""
Aegis NIDS - Network Defense System
Detects SYN Floods and logs attacks to CSV for dashboard visualization.
"""
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import os
import csv
import time
from datetime import datetime

# Configuration
SYN_THRESHOLD = 15
LOG_FILE = "alerts.csv"
scan_attempts = defaultdict(int)

def log_attack(src_ip, dst_ip, count):
    """
    Logs the attack details to a CSV file.
    """
    # Check if file exists to determine if we need to write headers
    file_exists = os.path.isfile(LOG_FILE)
    
    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        # If file is new, write the column headers first
        if not file_exists:
            writer.writerow(["Timestamp", "Attacker_IP", "Target_IP", "Attack_Type", "Count"])
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([timestamp, src_ip, dst_ip, "SYN Flood / Port Scan", count])

def packet_callback(packet):
    """
    Analyzes captured packets.
    """
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flags = packet[TCP].flags
        
        # Check for SYN flag (S) - Start of connection
        if flags == "S":
            scan_attempts[src_ip] += 1
            
            # Trigger alert if threshold is exceeded
            if scan_attempts[src_ip] > SYN_THRESHOLD:
                print(f"[!!!] ALERT: Port Scan Detected from {src_ip} -> {dst_ip}")
                
                # Log attack to CSV for the Dashboard
                log_attack(src_ip, dst_ip, scan_attempts[src_ip])
                
                # Reset counter to avoid duplicate logging for the same burst
                scan_attempts[src_ip] = 0

def main():
    # Clear terminal
    os.system("cls" if os.name == "nt" else "clear")
    
    print("==========================================")
    print("   AEGIS NIDS - DASHBOARD EDITION v2.0")
    print("==========================================")
    print(f"[-] Monitoring started. Logs are saved to: {LOG_FILE}")
    
    # Initialize/Reset the log file with headers
    with open(LOG_FILE, "w") as f:
        f.write("Timestamp,Attacker_IP,Target_IP,Attack_Type,Count\n")

    # Start sniffing TCP traffic
    sniff(filter="tcp", prn=packet_callback, store=False)

if __name__ == "__main__":
    main()