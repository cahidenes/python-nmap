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

def scan(ips, ports, method="half"):
    if method == "half" and not HALF_SCAN_AVAILABLE:
        print("Half scan is not available. Falling back to full scan.")
        method = "full"
    for ip in ips:
        for port in ports:
            if method == "half" and HALF_SCAN_AVAILABLE:
                result = half_scan(ip, port)
            else:
                result = full_scan(ip, port)
    
            if result:
                print(f"{ip}:{port} is open")

def main():
    conf.verb = 0
    if os.geteuid() != 0:
        print("WARNING: In order to run half_scan, you need to run this script with root privileges.")
        global HALF_SCAN_AVAILABLE
        HALF_SCAN_AVAILABLE = False

    scan(["10.40.31.13", "127.0.0.1"], [20, 21, 22, 23, 24, 25, 26, 27, 28], method="half")

if __name__ == "__main__":
    main()