from scapy.all import IP, TCP, sr1, conf
import socket
import os

HALF_SCAN_AVAILABLE = True

def half_scan(ip, port):
    source_port = 12345
    packet = IP(dst=ip)/TCP(sport=source_port, dport=port, flags='S')

    response = sr1(packet, timeout=1)
    if response is None:
        return False
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            return True
        elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
            return False

def full_scan(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception as e:
        return False

def main():
    conf.verb = 0
    if os.geteuid() != 0:
        print("WARNING: In order to run half_scan, you need to run this script with root privileges.")
        global HALF_SCAN_AVAILABLE
        HALF_SCAN_AVAILABLE = False

    print(full_scan("10.40.31.13", 22))

if __name__ == "__main__":
    main()