from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = "OTHER"
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        print(f"[{datetime.now().strftime('%H:%M:%S')}] {ip_layer.src} -> {ip_layer.dst} | Protocol: {proto}")
        with open("packet_log.txt", "a") as log_file:
            log_file.write(f"{datetime.now()} | {ip_layer.src} -> {ip_layer.dst} | Protocol: {proto}\n")

def main():
    print("⚠️ Running Packet Sniffer (For Educational Use Only)\n")
    sniff(filter="ip", prn=process_packet, store=False)

if __name__ == "__main__":
    main()
