#!/usr/bin/env python3
import argparse
import re
import sys
import socket
import binascii
import datetime
import os
import requests
import dns.resolver
from colorama import Fore, Style, init
from DNSDumpsterAPI import DNSDumpsterAPI
from collections.abc import Callable

# Initialize Colorama
init(Style.BRIGHT)

def print_out(data, end='\n'):
    datetimestr = datetime.datetime.now().strftime('%H:%M:%S')
    print(f"{Style.NORMAL}[{datetimestr}] {re.sub(' +', ' ', data)}{Style.RESET_ALL}", end=end)

def ip_in_subnetwork(ip_address, subnetwork):
    ip_integer, version1 = ip_to_integer(ip_address)
    ip_lower, ip_upper, version2 = subnetwork_to_ip_range(subnetwork)

    if version1 != version2:
        raise ValueError("Incompatible IP versions")

    return ip_lower <= ip_integer <= ip_upper

def ip_to_integer(ip_address):
    for version in (socket.AF_INET, socket.AF_INET6):
        try:
            ip_hex = socket.inet_pton(version, ip_address)
            ip_integer = int(binascii.hexlify(ip_hex), 16)
            return ip_integer, 4 if version == socket.AF_INET else 6
        except socket.error:
            continue
    raise ValueError("Invalid IP address")

def subnetwork_to_ip_range(subnetwork):
    try:
        network_prefix, netmask_len = subnetwork.split('/')
        netmask_len = int(netmask_len)
        for version in (socket.AF_INET, socket.AF_INET6):
            ip_len = 32 if version == socket.AF_INET else 128
            try:
                suffix_mask = (1 << (ip_len - netmask_len)) - 1
                netmask = ((1 << ip_len) - 1) - suffix_mask
                ip_hex = socket.inet_pton(version, network_prefix)
                ip_lower = int(binascii.hexlify(ip_hex), 16) & netmask
                ip_upper = ip_lower + suffix_mask
                return ip_lower, ip_upper, 4 if version == socket.AF_INET else 6
            except socket.error:
                continue
    except ValueError:
        pass
    raise ValueError("Invalid subnetwork")

def dnsdumpster(target):
    print_out(Fore.CYAN + "Testing for misconfigured DNS using dnsdumpster...")
    res = DNSDumpsterAPI(False).search(target)

    for record_type in ['host', 'dns', 'mx']:
        for entry in res['dns_records'].get(record_type, []):
            provider = str(entry['provider'])
            if "Cloudflare" not in provider:
                fields = ' '.join(f'{key}: {value}' for key, value in entry.items())
                print_out(f"{Style.BRIGHT}{Fore.WHITE}[FOUND:{record_type.upper()}] {Fore.GREEN}{fields}")

def crimeflare(target):
    print_out(Fore.CYAN + "Scanning crimeflare database...")
    crimeFoundArray = []
    try:
        with open("data/ipout", "r") as ins:
            crimeFoundArray = [line.split(" ")[2] for line in ins if line.split(" ")[1] == target]
    except IOError:
        print_out(Fore.RED + "Data file missing, cannot perform crimeflare scan.")
    
    if crimeFoundArray:
        for foundIp in crimeFoundArray:
            print_out(f"{Style.BRIGHT}{Fore.WHITE}[FOUND:IP] {Fore.GREEN}{foundIp.strip()}")
    else:
        print_out("Did not find anything.")

def init(target):
    if not target:
        print_out(Fore.RED + "No target set, exiting")
        sys.exit(1)

    print_out(Fore.CYAN + f"Fetching initial information from: {target}...")
    if not os.path.isfile("data/ipout"):
        print_out(Fore.CYAN + "No ipout file found, fetching data")
        update()
        print_out(Fore.CYAN + "ipout file created")

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print_out(Fore.RED + "Domain is not valid, exiting")
        sys.exit(0)

    print_out(Fore.CYAN + f"Server IP: {ip}")
    print_out(Fore.CYAN + f"Testing if {target} is on the Cloudflare network...")

    if inCloudFlare(ip):
        print_out(f"{Style.BRIGHT}{Fore.GREEN}{target} is part of the Cloudflare network!")
    else:
        print_out(Fore.RED + f"{target} is not part of the Cloudflare network, quitting...")
        sys.exit(0)

def inCloudFlare(ip):
    with open('data/cf-subnet.txt') as f:
        return any(ip_in_subnetwork(ip, line.strip()) for line in f)

def check_for_wildcard(target):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']
    try:
        resolver.resolve(f'*.{target}')
        while (choice := input("A wildcard DNS entry was found. This will result in all subdomains returning an IP. Do you want to scan subdomains anyway? (y/n): ")) not in {'y', 'n'}:
            pass
        return choice == 'n'
    except dns.exception.DNSException:
        return False

def subdomain_scan(target, subdomains):
    if check_for_wildcard(target):
        print_out(Fore.CYAN + "Scanning finished...")
        return

    subdomains_file = f"data/{subdomains}" if subdomains else "data/subdomains.txt"
    try:
        with open(subdomains_file, "r") as wordlist:
            numOfLines = sum(1 for _ in open(subdomains_file))
            print_out(Fore.CYAN + f"Scanning {numOfLines} subdomains ({subdomains_file}), please wait...")
            for i, word in enumerate(wordlist, 1):
                if i % (numOfLines // 100) == 0:
                    print_out(Fore.CYAN + f"{round((i / numOfLines) * 100, 2)}% complete", end='\r')

                subdomain = f"{word.strip()}.{target}"
                try:
                    target_http = requests.get(f"http://{subdomain}")
                    ip = socket.gethostbyname(subdomain)
                    if not inCloudFlare(ip):
                        print_out(f"{Style.BRIGHT}{Fore.WHITE}[FOUND:SUBDOMAIN] {Fore.GREEN}{subdomain} IP: {ip} HTTP: {target_http.status_code}")
                    else:
                        print_out(f"{Style.BRIGHT}{Fore.WHITE}[FOUND:SUBDOMAIN] {Fore.RED}{subdomain} ON CLOUDFLARE NETWORK!")
                except requests.RequestException:
                    continue
    except IOError:
        print_out(Fore.RED + "Subdomains file does not exist in data directory, aborting scan...")
        sys.exit(1)
    print_out(Fore.CYAN + "Scanning finished...")

def update():
    print_out(Fore.CYAN + "Just checking for updates, please wait...")
    print_out(Fore.CYAN + "Updating CloudFlare subnet...")
    if not args.tor:
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get("https://www.cloudflare.com/ips-v4", headers=headers, cookies={'__cfduid': "d7c6a0ce9257406ea38be0156aa1ea7a21490639772"}, stream=True)
        with open('data/cf-subnet.txt', 'wb') as fd:
            for chunk in r.iter_content(4000):
                fd.write(chunk)
    else:
        print_out(Fore.RED + Style.BRIGHT + "Unable to fetch CloudFlare subnet while TOR is active")
    
    print_out(Fore.CYAN + "Updating Crimeflare database...")
    r = requests.get("https://cf.ozeliurs.com/ipout", stream=True)
    with open('data/ipout', 'wb') as fd:
        for chunk in r.iter_content(4000):
            fd.write(chunk)

# Main script
logo = """\
   ____ _                 _ _____     _ _
  / ___| | ___  _   _  __| |  ___|_ _(_) |
 | |   | |/ _ \| | | |/ _` | |_ / _` | | |
 | |___| | (_) | |_| | (_| |  _| (_| | | |
  \____|_|\___/ \__,_|\__,_|_|  \__,_|_|_|
    v1.0.5                      by Light
"""

print(Fore.RED + Style.BRIGHT + logo + Fore.RESET)
print_out(f"Initializing CloudFail - the date is: {datetime.datetime.now().strftime('%d/%m/%Y')}")

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="target url of website", type=str)
parser.add_argument("-T", "--tor", dest="tor", action="store_true", help="enable TOR routing")
parser.add_argument("-u", "--update", dest="update", action="store_true", help="update databases")
parser.add_argument("-s", "--subdomains", help="name of alternate subdomains list stored in the data directory", type=str)
parser.set_defaults(tor=False)
parser.set_defaults(update=False)

args = parser.parse_args()

if args.tor:
    ipcheck_url = 'http://ipinfo.io/ip'
    import socks
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9050)
    socket.socket = socks.socksocket
    try:
        tor_ip = requests.get(ipcheck_url).text.strip()
        print_out(Fore.WHITE + Style.BRIGHT + f"TOR connection established! New IP: {tor_ip}")
    except requests.RequestException as e:
        print_out(Fore.RED + f"Error establishing TOR connection: {e}")
        sys.exit(0)

if args.update:
    update()

try:
    # Initialize CloudFail
    init(args.target)

    # Scan DNSdumpster.com
    dnsdumpster(args.target)

    # Scan Crimeflare database
    crimeflare(args.target)

    # Scan subdomains with or without TOR
    subdomain_scan(args.target, args.subdomains)

except KeyboardInterrupt:
    print_out(Fore.RED + "Operation interrupted by user.")
    sys.exit(0)