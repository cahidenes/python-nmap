from scapy.all import IP, TCP, sr1, conf
import os

HALF_SCAN_AVAILABLE = True

def half_scan(ip, port):
    source_port = 12345
    packet = IP(dst=ip)/TCP(sport=source_port, dport=port, flags='S')

    response = sr1(packet, timeout=1)
    if response is None:
        return 0
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            return 1
        elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
            return 0

def main():
    conf.verb = 0
    if os.geteuid() != 0:
        print("WARNING: In order to run half_scan, you need to run this script with root privileges.")
        global HALF_SCAN_AVAILABLE
        HALF_SCAN_AVAILABLE = False

    print(half_scan("10.40.31.13", 22))

if __name__ == "__main__":
    main()