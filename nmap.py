from scapy.all import IP, TCP, ICMP, sr1, conf
import socket
import argparse
import ipaddress
import os
import threading
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)   # suppress warnings
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

conf.verb = 0

opens = []
opens_lock = threading.Lock()

def half_scan(ip, port):
    source_port = 12345
    packet = IP(dst=ip)/TCP(sport=source_port, dport=port, flags='S')

    response = sr1(packet, timeout=1)
    if response is None:
        return False
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            with opens_lock:
                opens.append(f"{ip}:{port} open")
            return True
        elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
            return False

def full_scan(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            with opens_lock:
                opens.append(f"{ip}:{port} open")
        return result == 0
    except Exception as e:
        return False

def icmp_ping(ip):
    packet = IP(dst=ip)/ICMP()
    response = sr1(packet, timeout=1)
    if response is None:
        return False
    with opens_lock:
        opens.append(f"{ip} is alive")
    return True

def scan(ips, ports, method="half"):
    opens.clear()
    threads = []
    for ip in ips:
        if method == "ping":
            t = threading.Thread(target=icmp_ping, args=(ip,))
            threads.append(t)
            t.start()
        else:
            for port in ports:
                if method == "half":
                    t = threading.Thread(target=half_scan, args=(ip, port))
                else:
                    t = threading.Thread(target=full_scan, args=(ip, port))
                threads.append(t)
                t.start()

    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    opens.sort()
    for open in opens:
        print(open)

def parse_ips(target):
    ips = []
    for part in target.split(','):
        part = part.strip()
        if '/' in part:
            # CIDR notation
            try:
                network = ipaddress.ip_network(part, strict=False)
                ips.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                print(f"Invalid CIDR notation: {part}")
        else:
            ips.append(part)
    return ips

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            except ValueError:
                print(f"Invalid port range: {part}")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                print(f"Invalid port: {part}")
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(
        description="A simple port scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python nmap.py -t 192.168.1.1,192.168.1.2 -p 20-30 -m half
  python nmap.py --target 192.168.1.0/24 --ports 20-25,80,443 --method full
"""
        )
    parser.add_argument("-t", "--target", required=True, help="Target IP address(es) or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", required=True, help="Target port(s) (e.g., 80,443 or 20-30)")
    parser.add_argument("-m", "--method", choices=["ping", "half", "full"], default="half", help="Scan method to use (default: half)")
    args = parser.parse_args()
    ips = parse_ips(args.target)
    ports = parse_ports(args.ports)

    if args.method  in ["ping", "half"] and os.geteuid() != 0:
        print("ERROR: In order to run half_scan or ping, you need to run this script with root privileges.")
        exit(1)

    scan(ips, ports, method=args.method)

if __name__ == "__main__":
    # sample run: python3 nmap.py -t 10.40.31.13,127.0.0.1 -p 20-30
    main()