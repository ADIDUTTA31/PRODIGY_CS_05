from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import datetime
import os

def print_packet(packet):
    print("=" * 80)
    print("📦 Packet Captured at:", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if IP in packet:
        ip_layer = packet[IP]
        print(f"From: {ip_layer.src} -> To: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if TCP in packet:
            print("Layer: TCP")
            print(f"Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print("Layer: UDP")
            print(f"Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}")

        elif ICMP in packet:
            print("Layer: ICMP")
            print(f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}")

        if Raw in packet:
            try:
                payload = packet[Raw].load
                print("Payload (Raw):")
                print(payload.decode(errors='replace'))
            except Exception as e:
                print("Unable to decode payload.")
    else:
        print("Non-IP Packet")

# ❗ ETHICAL USE DISCLAIMER
print("***************************************************************")
print("This Packet Sniffer is for EDUCATIONAL USE ONLY.")
print("Do NOT use this tool to monitor unauthorized networks.")
print("***************************************************************\n")

# Start sniffing (requires admin/sudo rights)
try:
    interface = input("Enter interface to sniff on (e.g., eth0, wlan0): ").strip()
    print(f"\n🕵️ Sniffing on interface: {interface}. Press CTRL+C to stop.\n")
    sniff(iface=interface, prn=print_packet, store=False)
except PermissionError:
    print("❌ You must run this script as administrator/root!")
except KeyboardInterrupt:
    print("\n🛑 Sniffing stopped by user.")
except Exception as e:
    print(f"❌ Error: {e}")
