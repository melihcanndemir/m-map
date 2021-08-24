# M - MAP is an easy port scan tool
# Created by Melih Can
# Version 1.5
# Date 21/08/2021

from colorama import Fore
from datetime import datetime
import colorama
import pyfiglet
import sys
import socket
import os

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

while True:
    # Add Banner
    ascii_banner = pyfiglet.figlet_format("M - MAP")
    print(Fore.LIGHTBLUE_EX)
    print(ascii_banner)
    print(Fore.LIGHTGREEN_EX)
    print("M - MAP is an easy port scan tool")
    print(Fore.LIGHTWHITE_EX)
    # Get known services
    def get_service(ports):
        ports = str(ports)
        if ports in common_ports:
            return common_ports[ports]
        else:
            return 0

    choose_banner = '''
    1 - Single Port Scan
    2 - Multi Port Scan
    3 - Help
    4 - About
    5 - Exit
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

    if choose == "1":
        ip = input("Enter the IP Address: ")
        port = int(input("Enter the Port Number: "))
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        print("-"*50)
        if sock.connect_ex((ip,port)):
            print("Port ",port, "is closed")
        else:
            service = get_service(port)
            if not service:
                service = "UNKNOWN SERVICE"
            print(f"      {port}        OPEN       {service}")
            print("-"*50)
            print(Fore.LIGHTBLUE_EX)
            print(" ---- Scan is completed ----\n")

    elif choose == "2":
        try:
            value = int(input("Enter port range to scan (1 - 65535): "))
            target = input("Enter the target: ")

        except TypeError:
            print("\n Error !!! Please enter the true value.")
            sys.exit()

        except KeyboardInterrupt:
            print("\n KeyboardInterrupt Error")
            print("Exitting Program !!!!")
            sys.exit()

        # Defining a target
        # translate hostname to IPv4
        target = socket.gethostbyname(target)
        # Gets the current date
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
                socket.setdefaulttimeout(0.1)
                # Attempts to connect to target ports
                result = s.connect_ex((target,port))
                if result == 0:
                    service = get_service(port)
                    if not service:
                        service = "UNKNOWN SERVICE"
                    print(f"      {port}        OPEN       {service}")
                s.close()
            print(Fore.LIGHTBLUE_EX)
            print(" ---- Scan is completed ----\n")
            print("-"*50)
        # if uses Ctrl+C  etc. show this  
        except KeyboardInterrupt:
            print("\n Exitting Program !!!!")
            sys.exit(1)
        # This shows your given hostname is invalid
        except socket.gaierror:
            print("\n Hostname Could Not Be Resolved !!!!")
            sys.exit(1)
        # if Server not responding show this
        except socket.error:
            print("\n Server not responding !!!!")
            sys.exit(1)

    elif choose == "3":
        print("-"*50)
        print("\n How to use program ?")
        print("\n Program is easy to learn")
        print("-"*50)
        print("1 - Choose Option")
        print("2 - Write your target ip")
        print("3 - Write Port Range or Port number")
        print("4 - Wait... :)")
    
    elif choose == "4":
        print("-"*50)
        print("M - MAP is an easy port scan tool")
        print(" ")
        print("Created by Melih Can")    
        print("Version 1.5 Date 21/08/2021")
        print("-"*50)
        print("My E-mail: Melihcan1376@gmail.com")
        print("-"*50)
    
    elif choose == "5":
        os.system("cls")
        sys.exit(1)

    else:
        print("Choose Error! Please choose true option.")
    
    input()