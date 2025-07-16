from scapy.all import ARP, sniff
from collections import defaultdict
import json
import time
import os

mac_to_ips = defaultdict(set)
LOG_FILE = "logs/arp_logs.json"
os.makedirs("logs", exist_ok=True)

def log_alert(mac, ips):
    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "spoofed_mac": mac,
        "conflicting_ips": list(ips),
        "action": "logged"
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    print(f"[⚠️ ALERT] {mac} is used by multiple IPs: {ips}")
    os.system("afplay /System/Library/Sounds/Glass.aiff")

def process_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        mac = packet[ARP].hwsrc
        ip = packet[ARP].psrc
        mac_to_ips[mac].add(ip)
        print(f"[DEBUG] {ip} → {mac}")
        print(f"[DEBUG] Current IPs for {mac}: {mac_to_ips[mac]}")
        print(f"[DEBUG] Full mapping: {dict(mac_to_ips)}")
        if len(mac_to_ips[mac]) > 1:
            log_alert(mac, mac_to_ips[mac])

def start_sniffing():
    print("[*] ARP Detector Running... Press Ctrl+C to stop.")
    sniff(filter="arp", prn=process_packet, store=0)

if __name__ == "__main__":
    start_sniffing()
