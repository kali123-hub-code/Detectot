from scapy.all import sniff, TCP, IP
from collections import defaultdict
from datetime import datetime
import time

# Thresholds
PORT_SCAN_THRESHOLD = 10
SYN_FLOOD_THRESHOLD = 100
UNUSUAL_PORTS = {1337, 31337, 6667}

# Tracking
scan_tracker = defaultdict(list)
syn_tracker = defaultdict(int)

LOG_FILE = "intrusion_log.txt"

def log_intrusion(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")
    print(f"[ALERT] {message}")

def detect_intrusion(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # Port scan detection
        current_time = time.time()
        scan_tracker[src_ip].append((dst_port, current_time))
        # Keep only recent connections
        scan_tracker[src_ip] = [
            (port, t) for port, t in scan_tracker[src_ip] if current_time - t < 10
        ]
        unique_ports = {p for p, _ in scan_tracker[src_ip]}
        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            log_intrusion(f"Port scan detected from {src_ip} ({len(unique_ports)} ports)")

        # SYN Flood detection
        if flags == 'S':  # SYN
            syn_tracker[src_ip] += 1
            if syn_tracker[src_ip] > SYN_FLOOD_THRESHOLD:
                log_intrusion(f"SYN Flood detected from {src_ip} ({syn_tracker[src_ip]} SYNs)")

        # Unusual port access
        if dst_port in UNUSUAL_PORTS:
            log_intrusion(f"Suspicious port access: {src_ip} tried port {dst_port}")

def start_sniffing():
    print("Starting packet sniffing... (Press Ctrl+C to stop)")
    sniff(filter="tcp", prn=detect_intrusion, store=0)

if __name__ == "__main__":
    start_sniffing()
