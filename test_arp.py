# test_arp.py
from scapy.all import ARP, Ether, sendp
import time

iface = "en0"

# Packet 1
p1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2, psrc="192.168.31.1", pdst="192.168.31.10",
    hwsrc="de:ad:be:ef:00:00", hwdst="ff:ff:ff:ff:ff:ff"
)

# Packet 2
p2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2, psrc="192.168.31.99", pdst="192.168.31.11",
    hwsrc="de:ad:be:ef:00:00", hwdst="ff:ff:ff:ff:ff:ff"
)

sendp(p1, iface=iface)
time.sleep(1)
sendp(p2, iface=iface)
