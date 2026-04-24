#!/usr/bin/env python3
# File name   : cssltd_webosint.py
# Tool name   : CSSLTD WebOSINT
# Version     : V3.0 (Refactored)
# Licence     : MIT

import os
import re
import json
import socket
import argparse
from datetime import datetime
from pprint import pformat

import requests
import whois
from dateutil.parser import parse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

# Init Rich Console
console = Console()

class ConfigLoader:
    def __init__(self, config_path="config.json"):
        self.config_path = config_path
        self.keys = {
            'WHOIS_XML_API_KEY': None,
            'HACKERTARGET_API_KEY': None,
            'WHOIS_FREAKS_API_KEY': None
        }
        self.load()

    def load(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                    for k in self.keys:
                        self.keys[k] = data.get(k, None)
            except Exception as e:
                console.print(f"[bold red][!] Error loading config file: {e}[/bold red]")


class WebOSINT:
    def __init__(self, domain, config):
        self.domain = domain
        self.config = config
        self.ip_address = None
        self.results = {"domain": self.domain, "timestamp": datetime.now().isoformat()}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CSSLTD-WebOSINT/3.0"})

    def check_registration(self):
        console.print(f"[bold blue][*] Checking domain registration: {self.domain}[/bold blue]")
        try:
            dn = whois.whois(self.domain)
            is_registered = bool(dn.domain_name)
        except Exception:
            is_registered = False

        self.results['is_registered'] = is_registered
        if is_registered:
            console.print("[bold green][+] Domain is registered.[/bold green]")
        else:
            console.print("[bold red][-] Domain is probably NOT registered.[/bold red]")

    def get_ip_data(self):
        console.print(f"\n[bold blue][*] Resolving IP address...[/bold blue]")
        try:
            self.ip_address = socket.gethostbyname(self.domain)
            self.results['ip'] = self.ip_address
            console.print(f"[bold green][+] IP Address: {self.ip_address}[/bold green]")
            
            resp = self.session.get(f'https://ipinfo.io/{self.ip_address}/json').json()
            self.results['ip_info'] = resp
            
            table = Table(title="IP Information (ipinfo.io)")
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="magenta")
            
            for k, v in resp.items():
                if k != "readme":
                    table.add_row(str(k), str(v))
            console.print(table)
            
        except socket.gaierror:
            console.print("[bold red][!] Failed to resolve domain IP address.[/bold red]")

    def reverse_ip(self):
        if not self.ip_address:
            console.print("[bold yellow][!] No IP available for Reverse IP lookup.[/bold yellow]")
            return

        console.print("\n[bold blue][*] Reverse IP Lookup (HackerTarget)...[/bold blue]")
        api_key = self.config.keys['HACKERTARGET_API_KEY']
        
        if api_key:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={self.ip_address}&apikey={api_key}"
        else:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={self.ip_address}"

        try:
            resp = self.session.get(url)
            if resp.status_code == 200 and "API count exceeded" not in resp.text:
                domains = resp.text.splitlines()
                self.results['reverse_ip'] = domains
                console.print(f"[bold green][+] Domains found on the same IP: {len(domains)}[/bold green]")
            else:
                console.print(f"[bold yellow][!] Error or free API limit reached: {resp.text.strip()}[/bold yellow]")
        except Exception as e:
            console.print(f"[bold red][!] Connection error: {e}[/bold red]")

    def get_dns_records(self):
        console.print("\n[bold blue][*] Fetching DNS records...[/bold blue]")
        api_key = self.config.keys['HACKERTARGET_API_KEY']
        
        if api_key:
            url = f"https://api.hackertarget.com/dnslookup/?q={self.domain}&apikey={api_key}"
        else:
            url = f"https://api.hackertarget.com/dnslookup/?q={self.domain}"

        try:
            resp = self.session.get(url)
            if resp.status_code == 200:
                self.results['dns_records'] = resp.text.splitlines()
                console.print(Panel(resp.text, title="DNS Records", border_style="cyan"))
            else:
                console.print(f"[bold yellow][!] API Error: {resp.text.strip()}[/bold yellow]")
        except Exception as e:
            console.print(f"[bold red][!] Connection error: {e}[/bold red]")

    def whois_search(self):
        console.print("\n[bold blue][*] Fetching WHOIS information...[/bold blue]")
        try:
            w = whois.whois(self.domain)
            w_data = dict(w)
            # Convert dates for JSON dump
            for k, v in w_data.items():
                if isinstance(v, datetime):
                    w_data[k] = v.isoformat()
                elif isinstance(v, list) and all(isinstance(i, datetime) for i in v):
                    w_data[k] = [i.isoformat() for i in v]

            self.results['whois'] = w_data
            
            table = Table(title="Standard WHOIS")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="magenta")
            
            table.add_row("Registrar", str(w.registrar))
            table.add_row("Creation Date", str(w.creation_date))
            table.add_row("Expiration Date", str(w.expiration_date))
            table.add_row("Name Servers", str(w.name_servers))
            console.print(table)
        except Exception as e:
            console.print(f"[bold red][!] WHOIS Error: {e}[/bold red]")

    def crt_sh(self):
        console.print("\n[bold blue][*] Scanning Certificates & Subdomains (crt.sh)...[/bold blue]")
        try:
            r = self.session.get(f'https://crt.sh/?q={self.domain}&output=json', timeout=15)
            if r.status_code == 200:
                data = r.json()
                subdomains = set()
                certs = []
                
                for c in track(data, description="Processing certificates..."):
                    name_value = c.get('name_value', '')
                    subdomains.update(name_value.split('\n'))
                    certs.append({
                        'id': c.get('id'),
                        'issuer': c.get('issuer_name'),
                        'not_before': c.get('not_before')
                    })
                
                self.results['crt_sh_subdomains'] = sorted(list(subdomains))
                self.results['crt_sh_certs_summary'] = certs[:10] # limit save to 10 for readability
                
                console.print(f"[bold green][+] Identified {len(subdomains)} unique subdomains.[/bold green]")
                for sub in sorted(list(subdomains))[:15]:
                    console.print(f"  - {sub}")
                if len(subdomains) > 15:
                    console.print("  ... and more (see export file).")
            else:
                 console.print("[bold red][!] Error communicating with crt.sh[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] crt.sh exception: {e}[/bold red]")

    def reputation(self):
        api_key = self.config.keys['WHOIS_XML_API_KEY']
        if not api_key:
            console.print("\n[bold yellow][!] Skipping reputation analysis (missing WHOIS_XML_API_KEY)[/bold yellow]")
            return

        console.print("\n[bold blue][*] Scanning domain reputation (WhoisXML)...[/bold blue]")
        try:
            url = f"https://domain-reputation.whoisxmlapi.com/api/v2?apiKey={api_key}&domainName={self.domain}"
            resp = self.session.get(url).json()
            self.results['reputation'] = resp
            console.print(Panel(pformat(resp), title="Reputation", border_style="cyan"))
        except Exception as e:
            console.print(f"[bold red][!] Reputation module error: {e}[/bold red]")

    def whois_history(self):
        api_key = self.config.keys['WHOIS_FREAKS_API_KEY']
        if not api_key:
            console.print("\n[bold yellow][!] Skipping WHOIS history (missing WHOIS_FREAKS_API_KEY)[/bold yellow]")
            return

        console.print("\n[bold blue][*] Fetching WHOIS history (WhoisFreaks)...[/bold blue]")
        try:
            url = f"https://api.whoisfreaks.com/v1.0/whois?apiKey={api_key}&whois=historical&domainName={self.domain}"
            resp = self.session.get(url).json()
            self.results['whois_history'] = resp
            console.print(Panel(pformat(resp.get('whois_records', [])[:2]), title="Recent WHOIS history entries", border_style="cyan"))
        except Exception as e:
            console.print(f"[bold red][!] WhoisFreaks module error: {e}[/bold red]")

    def export(self, filename):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)
        console.print(f"\n[bold green][+] Results successfully saved to: {filename}[/bold green]")

def banner():
    art = """[bold magenta]
    ██████╗███████╗███████╗██╗  ████████╗██████╗ 
   ██╔════╝██╔════╝██╔════╝██║  ╚══██╔══╝██╔══██╗
   ██║     ███████╗███████╗██║     ██║   ██║  ██║
   ██║     ╚════██║╚════██║██║     ██║   ██║  ██║
   ╚██████╗███████║███████║███████╗██║   ██████╔╝
    ╚═════╝╚══════╝╚══════╝╚══════╝╚═╝   ╚═════╝ 
    W E B   O S I N T   |   V 3 . 0   |  C L I
    [/bold magenta]"""
    console.print(art)

def main():
    parser = argparse.ArgumentParser(description="CSSLTD WebOSINT - Advanced domain recon.")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("--ip", action="store_true", help="Fetch IP data and geolocation")
    parser.add_argument("--rev-ip", action="store_true", help="Search for other domains on the same IP")
    parser.add_argument("--dns", action="store_true", help="Fetch DNS records")
    parser.add_argument("--whois", action="store_true", help="Perform standard WHOIS query")
    parser.add_argument("--subdomains", action="store_true", help="Search for certificates and subdomains on crt.sh")
    parser.add_argument("--reputation", action="store_true", help="Scan reputation (requires WHOIS_XML key)")
    parser.add_argument("--history", action="store_true", help="WHOIS History (requires WHOIS_FREAKS key)")
    parser.add_argument("--all", action="store_true", help="Run all modules above")
    parser.add_argument("-o", "--output", help="Path to save results in JSON format (e.g., result.json)")
    
    args = parser.parse_args()

    banner()
    config = ConfigLoader()
    engine = WebOSINT(args.domain, config)

    # Registration is basic - we always do it
    engine.check_registration()

    if args.ip or args.all:
        engine.get_ip_data()
    if args.rev_ip or args.all:
        engine.reverse_ip()
    if args.dns or args.all:
        engine.get_dns_records()
    if args.whois or args.all:
        engine.whois_search()
    if args.subdomains or args.all:
        engine.crt_sh()
    if args.reputation or args.all:
        engine.reputation()
    if args.history or args.all:
        engine.whois_history()

    if args.output:
        engine.export(args.output)
    
    console.print("\n[bold green][+] Recon completed.[/bold green]")

if __name__ == '__main__':
    main()
