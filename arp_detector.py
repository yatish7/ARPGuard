from scapy.all import ARP, sniff
import requests
from datetime import datetime
import time

ip_mac_map = {}

CLOUD_ENDPOINT = "https://arpguard.onrender.com/api/upload"  # No trailing slash

def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # is-at (ARP reply)
        real_ip = packet[ARP].psrc
        real_mac = packet[ARP].hwsrc

        print(f"[DEBUG] {real_ip} → {real_mac}")

        if real_mac in ip_mac_map:
            ip_mac_map[real_mac].add(real_ip)
        else:
            ip_mac_map[real_mac] = {real_ip}

        print(f"[DEBUG] Current IPs for {real_mac}: {ip_mac_map[real_mac]}")
        print(f"[DEBUG] Full mapping: {ip_mac_map}")

        if len(ip_mac_map[real_mac]) > 1:
            print(f"[⚠️ ALERT] {real_mac} is used by multiple IPs: {ip_mac_map[real_mac]}")

            # Prepare alert payload
            alert = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "mac": real_mac,
                "ips": list(ip_mac_map[real_mac])
            }

            try:
                response = requests.post(CLOUD_ENDPOINT, json=alert, timeout=5)
                if response.status_code == 200:
                    print("[✅] Alert uploaded successfully to cloud dashboard.")
                else:
                    print(f"[❌] Failed to upload alert: {response.status_code} {response.text}")
            except Exception as e:
                print(f"[❌] Exception during upload: {e}")

if __name__ == "__main__":
    print("[*] ARP Detector Running... Press Ctrl+C to stop.")
    sniff(filter="arp", store=False, prn=detect_arp_spoof)
