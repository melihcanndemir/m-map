# M - MAP is an easy port scan tool
# Created by Melih Can
# Version 1.6.0
# Date 21/08/2021

from colorama import Fore
from datetime import datetime
import colorama
import pyfiglet
import sys
import socket
import os
import threading
from queue import Queue
import time
import struct
import subprocess
import json
import requests
import argparse
import platform
import nmap

colorama.init()

# Most Used Ports
common_ports = {
 
	'21': 'FTP',
	'22': 'SSH',
	'23': 'TELNET',
	'25': 'SMTP',
	'53': 'DNS',
	'69': 'TFTP',
	'80': 'HTTP',
	'109': 'POP2',
	'110': 'POP3',
	'123': 'NTP',
	'137': 'NETBIOS-NS',
	'138': 'NETBIOS-DGM',
	'139': 'NETBIOS-SSN',
	'143': 'IMAP',
	'156': 'SQL-SERVER',
	'389': 'LDAP',
	'443': 'HTTPS',
	'546': 'DHCP-CLIENT',
	'547': 'DHCP-SERVER',
	'995': 'POP3-SSL',
	'993': 'IMAP-SSL',
	'2086': 'WHM/CPANEL',
	'2087': 'WHM/CPANEL',
	'2082': 'CPANEL',
	'2083': 'CPANEL',
	'3306': 'MYSQL',
	'8443': 'PLESK',
	'10000': 'VIRTUALMIN/WEBMIN'
}

# Quick scan ports
quick_scan_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                   993, 995, 1723, 3306, 3389, 5900, 8080]

def scan_port(target, ports, queue, progress_queue):
    if not ports:
        print("Port list is empty!")
        return
        
    # Her 1000 portta bir queue'yu boşalt
    results_buffer = []
    for port in ports:
        try:
            if not isinstance(port, int) or port < 1 or port > 65535:
                print(f"Invalid port number: {port}")
                continue
                
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.015)
            result = s.connect_ex((target, port))
            if result == 0:
                service = get_service(str(port))
                if not service:
                    service = "UNKNOWN SERVICE"
                results_buffer.append((port, service))
                if len(results_buffer) >= 1000:
                    for r in results_buffer:
                        queue.put(r)
                    results_buffer.clear()
            s.close()
            progress_queue.put(1)
        except:
            progress_queue.put(1)
    
    # Kalan sonuçları gönder
    for r in results_buffer:
        queue.put(r)

def save_results(target, results, scan_time):
    filename = f"scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w") as f:
        f.write(f"M-MAP Port Scan Report\n")
        f.write(f"Scanned Target: {target}\n")
        f.write(f"Scan Time: {scan_time}\n")
        f.write("-" * 50 + "\n")
        f.write("PORT      STATE      SERVICE\n")
        for port, service in sorted(results):
            f.write(f"{port:<10}OPEN       {service}\n")
    return filename

def get_service_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except:
        return None

def scan_ip_range(start_ip, end_ip, ports):
    try:
        def ip_to_int(ip):
            return struct.unpack('!I', socket.inet_aton(ip))[0]
        
        def int_to_ip(ip_int):
            return socket.inet_ntoa(struct.pack('!I', ip_int))
        
        start = ip_to_int(start_ip)
        end = ip_to_int(end_ip)
        
        if start > end:
            print("Start IP cannot be greater than end IP!")
            return
        
        for ip_int in range(start, end + 1):
            current_ip = int_to_ip(ip_int)
            print(f"\nScanning: {current_ip}")
            
            # Port scanning process
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            for port in ports:
                result = sock.connect_ex((current_ip, port))
                if result == 0:
                    service = get_service(str(port))
                    if not service:
                        service = "UNKNOWN SERVICE"
                    print(f"      {port}        OPEN       {service}")
            sock.close()

    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

def ping_scan(target):
    # Check if the IP address is valid
    try:
        socket.inet_aton(target)
    except socket.error:
        print("Invalid IP address!")
        return False
    try:
        output = subprocess.check_output(
            ['ping', '-n', '1', target] if os.name == 'nt' else ['ping', '-c', '1', target],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        if 'TTL=' in output or 'ttl=' in output:
            return True
    except:
        pass
    return False

def udp_scan(target, ports, queue, progress_queue):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
    except socket.error:
        print("Could not create socket!")
        return

    for port in ports:
        try:
            sock.sendto(b'', (target, port))
            try:
                data, addr = sock.recvfrom(1024)
                queue.put((port, "UDP OPEN"))
            except socket.timeout:
                # Port might be open if no response
                queue.put((port, "UDP OPEN|FILTERED"))
            progress_queue.put(1)
        except:
            progress_queue.put(1)
    
    sock.close()  # Close socket outside the loop

scan_speeds = {
    'Slow': {'timeout': 0.1, 'threads': 50},
    'Normal': {'timeout': 0.05, 'threads': 100},
    'Fast': {'timeout': 0.02, 'threads': 200},
    'Very Fast': {'timeout': 0.01, 'threads': 300}
}

def set_scan_speed():
    print("\nSelect Scan Speed:")
    for i, speed in enumerate(scan_speeds.keys(), 1):
        print(f"{i} - {speed}")
    choice = input("Your choice: ")
    return list(scan_speeds.values())[int(choice)-1]

def export_results(results, format_type, target):
    if not results:
        print("No results to export!")
        return None
    if format_type == 'txt':
        return save_results(target, results, datetime.now())
    elif format_type == 'json':
        data = {
            'target': target,
            'scan_time': str(datetime.now()),
            'open_ports': [{
                'port': port,
                'service': service
            } for port, service in results]
        }
        filename = f"scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        return filename

def check_for_updates():
    current_version = "1.5"
    try:
        # Check for latest version from GitHub or other source
        response = requests.get("https://api.github.com/repos/user/m-map/releases/latest")
        latest_version = response.json()["tag_name"]
        if latest_version > current_version:
            print(f"New version available! Current: {current_version}, Latest: {latest_version}")
    except:
        pass

def detect_os(target):
    try:
        nm = nmap.PortScanner()
        result = nm.scan(target, arguments='-O')
        
        if 'osmatch' in result['scan'][target]:
            os_matches = result['scan'][target]['osmatch']
            if os_matches:
                return os_matches[0]['name']
        return "Operating system detection failed"
    except Exception as e:
        return f"OS detection error: {str(e)}"

def parse_arguments():
    parser = argparse.ArgumentParser(description='M-MAP Port Scanner')
    parser.add_argument('-t', '--target', help='Target IP address')
    parser.add_argument('-p', '--port', help='Port number or port range (e.g., 80 or 20-100)')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan (top 20 ports)')
    parser.add_argument('-o', '--output', help='Save results to file (txt or json)')
    return parser.parse_args()

def network_scan(subnet):
    """Scans for active hosts in the specified subnet"""
    print(f"\nStarting network scan: {subnet}")
    active_hosts = []
    
    # Example: 192.168.1.0/24
    base_ip = subnet.split('/')[0]
    base_parts = base_ip.split('.')
    
    for i in range(1, 255):
        ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}"
        if ping_scan(ip):
            print(f"\rActive host found: {ip}")
            active_hosts.append(ip)
    
    return active_hosts

def export_html_report(results, target, scan_time):
    filename = f"scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    html_content = f"""
    <html>
    <head>
        <title>M-MAP Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .header {{ background-color: #4CAF50; color: white; padding: 20px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>M-MAP Scan Report</h1>
            <p>Target: {target}</p>
            <p>Scan Time: {scan_time}</p>
        </div>
        <table>
            <tr>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
            </tr>
    """
    
    for port, service in sorted(results):
        html_content += f"""
            <tr>
                <td>{port}</td>
                <td>OPEN</td>
                <td>{service}</td>
            </tr>
        """
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filename

def get_service(ports):
    ports = str(ports)
    if ports in common_ports:
        return common_ports[ports]
    else:
        return 0

def get_optimal_thread_count():
    """Get optimal thread count based on CPU cores"""
    return min(200, os.cpu_count() * 4)  # Maximum 200 threads

# Pyfiglet font yolu için
def get_font_path():
    try:
        import sys
        import os
        if getattr(sys, 'frozen', False):
            # PyInstaller ile paketlenmiş
            base_path = sys._MEIPASS
        else:
            # Normal Python
            import pyfiglet
            base_path = os.path.dirname(pyfiglet.__file__)
        return os.path.join(base_path, 'pyfiglet', 'fonts')
    except:
        return None

def validate_ip(ip_address: str) -> bool:
    """IP adresinin geçerli olup olmadığını kontrol eder."""
    try:
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except (AttributeError, TypeError, ValueError):
        return False

def validate_subnet(subnet: str) -> bool:
    """Subnet'in geçerli olup olmadığını kontrol eder."""
    try:
        if '/' not in subnet:
            return False
        ip, mask = subnet.split('/')
        if not validate_ip(ip):
            return False
        mask = int(mask)
        return 0 <= mask <= 32
    except (ValueError, AttributeError):
        return False

def get_service_name(port: int) -> str:
    """Port numarasına göre servis ismini döndürür."""
    common_ports = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        3306: "mysql",
        5432: "postgresql"
    }
    return common_ports.get(port, "unknown")

def parse_port_range(port_range: str) -> list:
    """Port aralığını parse eder ve port listesi döndürür."""
    try:
        ports = []
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(ports)
    except ValueError:
        raise ValueError("Geçersiz port aralığı formatı")

def scan_port(target: str, port: int, timeout: int = 1) -> bool:
    """
    Belirtilen portu tarar.
    
    Args:
        target: Hedef IP adresi
        port: Taranacak port
        timeout: Bağlantı zaman aşımı (saniye)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except:
        return False

def resolve_host(hostname: str) -> str:
    """
    Hostname'i IP adresine çözümler.
    
    Args:
        hostname: Çözümlenecek hostname
    Returns:
        str: IP adresi veya boş string (çözümlenemezse)
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""

def get_banner(target: str, port: int, timeout: int = 2) -> str:
    """
    Belirtilen port üzerinden banner bilgisini alır.
    
    Args:
        target: Hedef IP adresi
        port: Bağlanılacak port
        timeout: Zaman aşımı süresi (saniye)
    Returns:
        str: Banner bilgisi veya boş string
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()
    except (socket.timeout, socket.error):
        return ""

def detect_service(target: str, port: int) -> str:
    """
    Port üzerinde çalışan servisi tespit eder.
    
    Args:
        target: Hedef IP adresi
        port: Kontrol edilecek port
    Returns:
        str: Tespit edilen servis adı ve versiyonu
    """
    banner = get_banner(target, port)
    
    # HTTP/HTTPS kontrolü
    if "HTTP" in banner:
        service = "HTTP"
        if "nginx" in banner.lower():
            service += " (nginx)"
        elif "apache" in banner.lower():
            service += " (Apache)"
        return service
    
    # SSH kontrolü
    if "SSH" in banner:
        service = "SSH"
        if "OpenSSH" in banner:
            version = banner.split("OpenSSH_")[1].split()[0]
            service += f" (OpenSSH {version})"
        return service
    
    # Bilinmeyen servis
    return "Unknown"

def show_about():
    """Display program information and check for updates"""
    version_info = {
        'name': 'M-MAP',
        'version': '1.6.0',
        'author': 'Melih Can',
        'email': 'melihcandemir@protonmail.com',
        'github': 'https://github.com/melihcan1376/m-map',
        'license': 'MIT',
        'year': '2025',
        'description': 'Advanced Port Scanner and Network Mapping Tool'
    }

    # Stil için ANSI renk kodları
    BLUE = Fore.LIGHTBLUE_EX
    GREEN = Fore.LIGHTGREEN_EX
    WHITE = Fore.LIGHTWHITE_EX
    RESET = Fore.RESET

    print(f"\n{BLUE}{'='*50}{RESET}")
    
    # ASCII banner'ı ekle
    try:
        ascii_banner = pyfiglet.figlet_format("M - MAP")
    except:
        ascii_banner = r"""
 __  __   __  __   _    ____  
|  \/  | |  \/  | / \  |  _ \ 
| |\/| | | |\/| |/ _ \ | |_) |
| |  | | | |  | / ___ \|  __/ 
|_|  |_| |_|  |_/_/   \_\_|    
        """
    print(f"{GREEN}{ascii_banner}{RESET}")
    
    print(f"{GREEN}{version_info['name']}{RESET} - {version_info['description']}")
    print(f"\n{WHITE}Version Information:{RESET}")
    print(f"  • Version: {version_info['version']}")
    print(f"  • Release Year: {version_info['year']}")
    print(f"  • License: {version_info['license']}")
    
    print(f"\n{WHITE}Developer:{RESET}")
    print(f"  • {version_info['author']}")
    print(f"  • {version_info['email']}")
    print(f"  • {version_info['github']}")
    
    print(f"\n{WHITE}Features:{RESET}")
    print("  • TCP/UDP Port Scanning")
    print("  • Service Detection")
    print("  • OS Detection")
    print("  • Network Scanning")
    print("  • Banner Grabbing")
    print("  • Multi-threading Support")
    print("  • Export (TXT/JSON/HTML)")
    
    print(f"\n{WHITE}Checking for updates...{RESET}")
    try:
        current_version = version_info['version']
        response = requests.get(
            "https://api.github.com/repos/melihcan1376/m-map/releases/latest",
            timeout=5
        )
        latest_version = response.json()["tag_name"]
        
        if latest_version > current_version:
            print(f"{GREEN}New version available!{RESET}")
            print(f"Current: {current_version}")
            print(f"Latest: {latest_version}")
            print(f"Update at: {version_info['github']}/releases")
        else:
            print(f"{GREEN}You have the latest version!{RESET}")
    except Exception as e:
        print(f"{Fore.RED}Could not check for updates: Network error{RESET}")
    
    print(f"\n{BLUE}{'='*50}{RESET}")

if __name__ == "__main__":
    args = parse_arguments()
    
    # If command-line arguments are provided, process them
    if args.target:
        target = args.target
        if args.quick:
            # Quick scan
            choose = "3"
        elif args.port:
            if '-' in args.port:
                # Port range scan
                start_port, end_port = map(int, args.port.split('-'))
                choose = "2"
                value = end_port
            else:
                # Single port scan
                choose = "1"
                port = int(args.port)
        
        # Save results option
        if args.output:
            # Save results after scan
            if args.output.endswith('.json'):
                format_type = 'json'
            else:
                format_type = 'txt'
    
    # Main loop
    while True:
        # Add Banner
        try:
            # Önce varsayılan font ile dene
            ascii_banner = pyfiglet.figlet_format("M - MAP")
        except:
            try:
                # Hata alırsa özel font yolunu kullan
                font_path = get_font_path()
                if font_path:
                    pyfiglet.FigletFont.DEFAULT_FONT_PATH = font_path
                ascii_banner = pyfiglet.figlet_format("M - MAP")
            except:
                # Her şey başarısız olursa basit bir banner kullan
                ascii_banner = r"""
 __  __   __  __   _    ____  
|  \/  | |  \/  | / \  |  _ \ 
| |\/| | | |\/| |/ _ \ | |_) |
| |  | | | |  | / ___ \|  __/ 
|_|  |_| |_|  |_/_/   \_\_|    
                """
        print(Fore.LIGHTBLUE_EX)
        print(ascii_banner)
        print(Fore.LIGHTGREEN_EX)
        print("M - MAP is an easy port scan tool")
        print(Fore.LIGHTWHITE_EX)
        # Get known services

        choose_banner = '''
        1 - Single Port Scan
        2 - Multi Port Scan
        3 - Quick Scan (Top 20 Ports)
        4 - Aggressive Scan
        5 - IP Range Scan
        6 - Export Last Scan
        7 - Scan Settings
        8 - OS Detection
        9 - UDP Port Scan
        10 - Network Scan
        11 - Help
        12 - About
        13 - Exit
        '''
        print(choose_banner)
        try:
            choose = input("Choose option: ")
        
        except KeyboardInterrupt:
            print("\n Exitting Program !!!!")
            sys.exit(1)
        
        except TypeError:
                print("\n Error !!! Please enter the true value.")
                sys.exit(1)

        if choose == "1":  # Single Port Scan
            ip = input("Enter IP Address: ")
            port = int(input("Enter Port Number: "))
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            print("-"*50)
            if sock.connect_ex((ip,port)):
                print(f"Port {port} closed")
            else:
                service = get_service(port)
                if not service:
                    service = "UNKNOWN SERVICE"
                print(f"      {port}        OPEN       {service}")
                print("-"*50)
                print(Fore.LIGHTBLUE_EX)
                print(" ---- Scan is completed ----\n")

        elif choose == "2":  # Multi Port Scan
            try:
                value = int(input("Enter port range to scan (1 - 65535): "))
                target = input("Enter the target: ")
                thread_count = get_optimal_thread_count()

                target = socket.gethostbyname(target)
                now = datetime.now()

                print(Fore.LIGHTGREEN_EX)
                print("-"*50)
                print("Scanning Target: " + target)
                print("Scanning started at: " + str(now.strftime("%d/%m/%Y %H:%M:%S")))
                print("-"*50)
                print(Fore.LIGHTWHITE_EX)
                print("      PORT      STATE      SERVICE")
                print("-"*50)

                queue = Queue()
                progress_queue = Queue()  # Progress queue
                threads = []
                total_ports = value
                scanned_ports = 0

                # Group ports based on thread count
                ports_per_thread = (value - 1) // thread_count + 1
                for i in range(0, value - 1, ports_per_thread):
                    port_group = range(i + 1, min(i + ports_per_thread + 1, value))
                    thread = threading.Thread(target=scan_port, args=(target, port_group, queue, progress_queue))
                    thread.daemon = True
                    threads.append(thread)

                # Start all threads
                for thread in threads:
                    thread.start()

                # Show progress
                while any(thread.is_alive() for thread in threads):
                    while not progress_queue.empty():
                        scanned_ports += progress_queue.get()
                    progress = (scanned_ports / total_ports) * 100
                    print(f"\rScan progress: %{progress:.1f} ({scanned_ports}/{total_ports} ports)", end="", flush=True)
                    time.sleep(0.1)

                # Get remaining progress
                while not progress_queue.empty():
                    scanned_ports += progress_queue.get()

                # Show final progress
                print(f"\rScan progress: %100.0 ({total_ports}/{total_ports} ports)")
                print("\n")

                # Print results in sorted order
                results = []
                while not queue.empty():
                    results.append(queue.get())
                
                if results:
                    for port, service in sorted(results):
                        print(f"      {port}        OPEN       {service}")
                else:
                    print("No open ports found.")

                print(Fore.LIGHTBLUE_EX)
                print(" ---- Scan is completed ----\n")
                print("-"*50)

            except KeyboardInterrupt:
                print("\n Exitting Program !!!!")
                sys.exit(1)
            except socket.gaierror:
                print("\n Hostname Could Not Be Resolved !!!!")
                sys.exit(1)
            except socket.error:
                print("\n Server not responding !!!!")
                sys.exit(1)

        elif choose == "3":  # Quick Scan
            try:
                target = input("Enter the target: ")
                target = socket.gethostbyname(target)
                now = datetime.now()

                print(Fore.LIGHTGREEN_EX)
                print("-"*50)
                print("Quick Scanning Target: " + target)
                print("Scanning started at: " + str(now.strftime("%d/%m/%Y %H:%M:%S")))
                print("-"*50)
                print(Fore.LIGHTWHITE_EX)
                print("      PORT      STATE      SERVICE")
                print("-"*50)

                queue = Queue()
                progress_queue = Queue()
                threads = []
                total_ports = len(quick_scan_ports)
                scanned_ports = 0

                # Scan top 20 ports
                thread = threading.Thread(target=scan_port, args=(target, quick_scan_ports, queue, progress_queue))
                thread.daemon = True
                thread.start()

                while thread.is_alive():
                    while not progress_queue.empty():
                        scanned_ports += progress_queue.get()
                    progress = (scanned_ports / total_ports) * 100
                    print(f"\rScan progress: %{progress:.1f} ({scanned_ports}/{total_ports} ports)", end="", flush=True)
                    time.sleep(0.1)

                thread.join()
                print("\n")

                results = []
                while not queue.empty():
                    results.append(queue.get())
                
                if results:
                    for port, service in sorted(results):
                        print(f"      {port}        OPEN       {service}")
                else:
                    print("No open ports found.")

                print(Fore.LIGHTBLUE_EX)
                print(" ---- Quick Scan Completed ----\n")
                print("-"*50)

            except Exception as e:
                print(f"\nError: {str(e)}")
                sys.exit(1)

        elif choose == "4":  # Aggressive Scan
            try:
                target = input("Enter the target: ")
                target = socket.gethostbyname(target)
                
                # First, check ping
                if not ping_scan(target):
                    print("Target is not responding!")
                    continue

                print("\nService version detection in progress...")
                queue = Queue()
                progress_queue = Queue()
                
                # Normal scan
                thread = threading.Thread(target=scan_port, args=(target, range(1, 1001), queue, progress_queue))
                thread.daemon = True
                thread.start()
                thread.join()

                results = []
                while not queue.empty():
                    port, service = queue.get()
                    # Get banner information
                    banner = get_service_banner(target, port)
                    if banner:
                        service = f"{service} ({banner})"
                    results.append((port, service))

                if results:
                    for port, service in sorted(results):
                        print(f"      {port}        OPEN       {service}")
                else:
                    print("No open ports found.")

            except Exception as e:
                print(f"\nError: {str(e)}")
                sys.exit(1)

        elif choose == "5":  # IP Range Scan
            try:
                start_ip = input("Enter start IP address: ")
                end_ip = input("Enter end IP address: ")
                port = int(input("Enter port to scan (single port): "))
                
                scan_ip_range(start_ip, end_ip, [port])

            except Exception as e:
                print(f"\nError: {str(e)}")
                sys.exit(1)

        elif choose == "6":  # Export Last Scan
            if 'results' not in locals():
                print("No scan has been performed yet!")
                continue

            print("\nSelect export format:")
            print("1 - TXT")
            print("2 - JSON")
            format_choice = input("Your choice: ")
            
            if format_choice == "1":
                filename = export_results(results, 'txt', target)
            elif format_choice == "2":
                filename = export_results(results, 'json', target)
            else:
                print("Invalid choice!")
                continue
            
            print(f"Results saved to {filename}")

        elif choose == "7":  # Scan Settings
            scan_config = set_scan_speed()
            print(f"New scan settings: Timeout={scan_config['timeout']}, Threads={scan_config['threads']}")

        elif choose == "8":  # OS Detection
            try:
                target = input("Enter the target IP: ")
                print("\nDetecting operating system...")
                os_info = detect_os(target)
                print(f"\nDetected operating system: {os_info}")
            except Exception as e:
                print(f"\nError: {str(e)}")

        elif choose == "9":  # UDP Port Scan
            try:
                target = input("Enter the target: ")
                port_range = int(input("Enter port range to scan (1 - 65535): "))
                
                print("\nStarting UDP port scan...")
                queue = Queue()
                progress_queue = Queue()
                
                thread = threading.Thread(target=udp_scan, 
                                       args=(target, range(1, port_range + 1), queue, progress_queue))
                thread.daemon = True
                thread.start()
                thread.join()
                
                results = []
                while not queue.empty():
                    results.append(queue.get())
                
                if results:
                    print("\nOpen UDP Ports:")
                    for port, status in sorted(results):
                        print(f"Port {port}: {status}")
                else:
                    print("No open UDP ports found.")
                    
            except Exception as e:
                print(f"\nError: {str(e)}")

        elif choose == "10":  # Network Scan
            try:
                subnet = input("Enter subnet (Example: 192.168.1.0/24): ")
                active_hosts = network_scan(subnet)
                
                if active_hosts:
                    print("\nActive Hosts:")
                    for host in active_hosts:
                        print(f"- {host}")
                else:
                    print("\nNo active hosts found.")
                    
            except Exception as e:
                print(f"\nError: {str(e)}")

        elif choose == "11":  # Help
            print("-"*50)
            print("\nHow to use?")
            print("\n1 - Single Port Scan: Scans a single port")
            print("2 - Multi Port Scan: Scans a range of ports")
            print("3 - Quick Scan: Quickly scans top 20 common ports")
            print("4 - Aggressive Scan: Detailed service detection")
            print("5 - IP Range Scan: Scans IP range")
            print("6 - Export Last Scan: Export scan results")
            print("7 - Scan Settings: Configure scan settings")
            print("8 - OS Detection: Detect operating system")
            print("9 - UDP Port Scan: Scan UDP ports")
            print("10 - Network Scan: Scan local network")

        elif choose == "12":  # About
            show_about()

        elif choose == "13":  # Exit
            print("\nExiting program...")
            sys.exit(0)

        else:
            print("Invalid choice! Please enter a valid option.")
        
        input()