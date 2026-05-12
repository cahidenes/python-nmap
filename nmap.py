from scapy.all import IP, TCP, ICMP, sr1, conf
import socket
import argparse
import ipaddress
import os
import threading
import logging
from tqdm import tqdm
from rich.table import Table
from rich.console import Console
from rich import box

console = Console()

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

conf.verb = 0

opens = []
opens_lock = threading.Lock()

def half_scan(ip, port):
    progress.update(1)
    source_port = 12345
    packet = IP(dst=ip)/TCP(sport=source_port, dport=port, flags='S')

    response = sr1(packet, timeout=1)
    if response is None:
        return False
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            try:
                service = socket.getservbyport(port, "tcp")
            except Exception:
                service = "unknown"
            with opens_lock:
                opens.append(
                    ((int(ip.split(".")[0]), '.',
                     int(ip.split(".")[1]), '.',
                     int(ip.split(".")[2]), '.',
                     int(ip.split(".")[3])),
                     port, service))
            return True
        elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
            return False

def full_scan(ip, port):
    progress.update(1)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except:
            pass

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip().split("\n")[0] if result == 0 else ""
        sock.close()
        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except Exception:
                service = "unknown"
            with opens_lock:
                opens.append(
                    ((int(ip.split(".")[0]), '.',
                     int(ip.split(".")[1]), '.',
                     int(ip.split(".")[2]), '.',
                     int(ip.split(".")[3])),
                     port, service, banner))
        return result == 0
    except Exception as e:
        return False

def icmp_ping(ip):
    progress.update(1)
    packet = IP(dst=ip)/ICMP()
    response = sr1(packet, timeout=1)
    if response is None:
        return False
    with opens_lock:
        opens.append(((int(ip.split(".")[0]), '.',
                      int(ip.split(".")[1]), '.',
                      int(ip.split(".")[2]), '.',
                      int(ip.split(".")[3])), "alive"))
    return True

def scan(ips, ports, method="half"):
    opens.clear()
    threads = []
    for ip in ips:
        if method == "ping":
            t = threading.Thread(target=icmp_ping, args=(ip,))
            threads.append(t)
        else:
            for port in ports:
                if method == "half":
                    t = threading.Thread(target=half_scan, args=(ip, port))
                else:
                    t = threading.Thread(target=full_scan, args=(ip, port))
                threads.append(t)

    global progress
    progress = tqdm(total=len(threads), desc="Scanning", unit="port")

    for t in threads:
        t.start()

    for t in threads:
        t.join()
    
    progress.close()
    
    opens.sort()
    table = Table(title="Scan Results", box=box.ROUNDED, show_header=True, header_style="bold white", show_lines=True)
    if method == "full":
        table.add_column("IP", justify="left", style="cyan")
        table.add_column("Port", justify="left", style="green")
        table.add_column("Service", justify="left", style="yellow")
        table.add_column("Banner", justify="left", style="white")
        for ip, port, service, banner in opens:
            table.add_row(''.join(map(str, ip)), str(port), service, banner)
    elif method == "half":
        table.add_column("IP", justify="left", style="cyan")
        table.add_column("Port", justify="left", style="green")
        table.add_column("Service", justify="left", style="yellow")
        for ip, port, service in opens:
            table.add_row(''.join(map(str, ip)), str(port), service)
    else:
        table.add_column("IP", justify="left", style="cyan")
        table.add_column("Status", justify="left", style="green")
        for ip, status in opens:
            table.add_row(''.join(map(str, ip)), status)
    
    console.print(table)


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
    parser.add_argument("-p", "--ports", default='80', help="Target port(s) (e.g., 80,443 or 20-30), default: 80")
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
