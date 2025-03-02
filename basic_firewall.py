from scapy.all import sniff, IP, TCP
import socket

BLOCKED_IPS = ["192.168.1.10"] 
BLOCKED_PORTS = [80, 443] 

def packet_filter(packet):
    """ Callback function to process each captured packet """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
                print(f"[BLOCKED] Packet from {src_ip} to {dst_ip} (Blocked IP)")
                return

            if src_port in BLOCKED_PORTS or dst_port in BLOCKED_PORTS:
                print(f"[BLOCKED] Packet from {src_ip}:{src_port} to {dst_ip}:{dst_port} (Blocked Port)")
                return
        
        print(f"[ALLOWED] {src_ip} -> {dst_ip}")

print("Starting packet capture...")
sniff(prn=packet_filter, store=0, iface="eth0")