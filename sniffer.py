from scapy.all import sniff, IP, TCP, UDP

def analyze_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]

        print("\n========== Packet ==========")
        print(f"Source IP: {ip.src}")
        print(f"Destination IP: {ip.dst}")

        # Protocol detection
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Protocol: TCP")
            print(f"Source Port: {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Protocol: UDP")
            print(f"Source Port: {udp.sport}")
            print(f"Destination Port: {udp.dport}")

        else:
            print("Protocol: Other")

        # Payload (basic display)
        if packet.payload:
            print(f"Payload: {bytes(packet.payload)[:30]}")

print("🚀 Basic Network Sniffer Running...")

sniff(prn=analyze_packet, store=False, count=20)