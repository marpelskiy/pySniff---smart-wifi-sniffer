import sys
import threading
import os
import tldextract
import requests
from scapy.all import sniff, DNS, DNSQR, IP, ARP, Ether, srp
from collections import Counter
from datetime import datetime
from getmac import get_mac_address
from colorama import Fore, Style, init


init(autoreset=True)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_ROOT = os.path.join(SCRIPT_DIR, "network_reports")

#TELEGRAM SETTINGS
TELEGRAM_TOKEN = "tg_bot_token (@BotFather)"
CHAT_ID = "user_id_chat (@userinfobot)"
ENABLE_TG = False # Поставь True, когда вставишь токен / Set to True when you insert the token.

stats = {}
active = False
vendor_cache = {}
alerted_pairs = set()

def print_banner():
    banner = rf"""
    {Fore.CYAN}__________        _________☠_________ _________
    \______   \___.__/   _____/ \      \ |   |   |  \
     |     ___<   |  |\_____  \  /   |   \|   |   |  /
     |    |    \___  |/        \/    |    \   |   | /
     |____|    / ____/_______  /\____|__  /___|___/
               \/            \/         \/
    {Fore.YELLOW}>>  Sniffer & OSINT Tool | 1.0  | Telegram Alert Active
    """
    print(banner)

def send_tg_alert(ip, mac, domain):
    if not ENABLE_TG or (ip, domain) in alerted_pairs:
        return

    alerted_pairs.add((ip, domain))
    msg = (f"🚨 *pySNIFF ALERT*\n"
           f"🖥 *IP:* `{ip}`\n"
           f"🆔 *MAC:* `{mac}`\n"
           f"🌐 *Domain:* `{domain.upper()}`")

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        threading.Thread(target=lambda: requests.post(url, data={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"}), daemon=True).start()
    except: pass

def get_device_info(ip):
    if ip in vendor_cache and vendor_cache[ip] not in ["Scanning...", "Unknown"]:
        return vendor_cache[ip]

    mac = get_mac_address(ip=ip)
    if mac:
        vendor_cache[ip] = mac.upper()
        return vendor_cache[ip]
    return "Unknown"

def process_packet(packet):
    if not active:
        return

    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and packet.haslayer(IP):
        try:
            ip_src = packet[IP].src
            full_domain = packet.getlayer(DNSQR).qname.decode("utf-8").strip(".")

            ext = tldextract.extract(full_domain)
            short_name = f"{ext.domain}.{ext.suffix}"

            if not ext.suffix or "arpa" in full_domain:
                return

            dev_info = get_device_info(ip_src)
            timestamp = datetime.now().strftime("%H:%M:%S")


            color = Fore.WHITE
            if any(x in short_name for x in ["telemetry", "track", "adscore", "doubleclick"]):
                color = Fore.RED
            elif "google" in short_name or "microsoft" in short_name:
                color = Fore.BLUE


            if ip_src not in stats or short_name not in stats[ip_src]:
                send_tg_alert(ip_src, dev_info, short_name)

            print(f"{Fore.YELLOW}[{timestamp}] {Fore.CYAN}| {ip_src:<15} | {Fore.MAGENTA}{dev_info:<18} {Fore.CYAN}| {color}{short_name.upper():<20} {Fore.CYAN}| {Style.DIM}{full_domain}")


            if ip_src not in stats: stats[ip_src] = Counter()
            stats[ip_src][short_name] += 1

            folder_name = f"{ip_src}_{dev_info}".replace(".", "_").replace(":", "-")
            ip_dir = os.path.join(LOG_ROOT, f"dev_{folder_name}")
            os.makedirs(ip_dir, exist_ok=True)

            with open(os.path.join(ip_dir, "traffic.txt"), "a", encoding="utf-8") as f:
                f.write(f"{timestamp} | {short_name} | {full_domain}\n")
        except: pass

def show_stats():
    print(f"\n{Fore.CYAN}╔" + "═"*75 + "╗")
    print(f"{Fore.CYAN}║ {Fore.YELLOW}NETWORK AUDIT REPORT".ljust(85) + f"{Fore.CYAN}║")
    print(f"{Fore.CYAN}╠" + "═"*75 + "╣")
    for ip, domains in stats.items():
        dev = vendor_cache.get(ip, "Unknown")
        print(f"{Fore.CYAN}║ {Fore.GREEN}DEVICE: {ip} [{dev}]".ljust(85) + f"{Fore.CYAN}║")
        for domain, count in domains.most_common(5):
            print(f"{Fore.CYAN}║   {Fore.WHITE}- {domain:<50} | {count:>5} hits {Fore.CYAN}║")
    print(f"{Fore.CYAN}╚" + "═"*75 + "╝\n")

def input_thread():
    global active
    print_banner()
    print(f"{Fore.WHITE}Commands: {Fore.GREEN}[S] Start {Fore.WHITE}| {Fore.RED}[P] Pause {Fore.WHITE}| {Fore.YELLOW}[ST] Stats {Fore.WHITE}| [Q] Quit")

    while True:
        cmd = input(f"{Fore.CYAN}pySniff >> ").lower().strip()
        if cmd == 's':
            active = True
            print(f"\n{Fore.GREEN}{'TIME':<10} | {'IP ADDRESS':<15} | {'MAC ADDRESS':<18} | {'DOMAIN':<20} | {'FULL URL'}")
            print("-" * 115)
        elif cmd == 'p':
            active = False
            print(f"\n{Fore.RED}[PAUSED]\n")
        elif cmd == 'st':
            show_stats()
        elif cmd == 'q':
            os._exit(0)

def main():
    if not os.path.exists(LOG_ROOT): os.makedirs(LOG_ROOT, exist_ok=True)
    t = threading.Thread(target=input_thread, daemon=True)
    t.start()
    try:
        sniff(filter="udp port 53", prn=process_packet, store=0)
    except:
        os._exit(1)

if __name__ == "__main__":
    main()
