# M - MAP is an easy port scan tool
# Created by Melih Can
# Date 21/08/2021

from colorama import Fore, Back, Style
from datetime import datetime
import colorama
import pyfiglet
import sys
import socket
import os
import time

os.system("cls")
colorama.init()

ascii_banner = pyfiglet.figlet_format("M - MAP")
print(Fore.LIGHTBLUE_EX)
print(ascii_banner)
print(Fore.LIGHTGREEN_EX)
print("M - MAP is an easy port scan tool")
print(Fore.LIGHTWHITE_EX)

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

def get_service(ports):
    ports = str(ports)
    if ports in common_ports:
        return common_ports[ports]
    else:
        return 0

try:
    value = int(input("Enter port range to scan (1 - 65535): "))
    timeout = float(input("Port Scanner Timeout: "))
    target = input("Enter the target: ")

except:
    print("Error !!! Please enter the true value.")
    sys.exit()

# Defining a target
# translate hostname to IPv4
target = socket.gethostbyname(target)
now = datetime.now()

# Add Banner
print(Fore.LIGHTGREEN_EX)
print("-"*50)
print("Scanning Target: " + target)
print("Scanning started at: " + str(now.strftime("%d/%m/%Y %H:%M:%S")))
print("-"*50)
print(Fore.LIGHTWHITE_EX)
print("      PORT      STATE      SERVICE")
print("-"*50)
try:
    # will scan ports between 1 to 65.535
    for port in range(1,value):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(timeout)
        # returns an error indicator
        result = s.connect_ex((target,port))
        if result == 0:
            service = get_service(port)
            if not service:
                service = "UNKNOWN SERVICE"
            print(f"      {port}        OPEN       {service}")
        s.close()

except KeyboardInterrupt:
    print("\n Exitting Program !!!!")
    sys.exit(1)

except socket.gaierror:
    print("\n Hostname Could Not Be Resolved !!!!")
    sys.exit(1)

except socket.error:
    print("\n Server not responding !!!!")
    sys.exit(1)

print("-"*50)
print(Fore.LIGHTBLUE_EX)
print(" ---- Scan is completed ----\n")
print(Fore.LIGHTRED_EX)
input("Press Close to Exit...")