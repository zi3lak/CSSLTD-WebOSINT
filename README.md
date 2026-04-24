CSSLTD WebOSINT
Advanced, passive CLI tool for Domain Intelligence and Open Source Intelligence (OSINT). 
Designed for automation, speed, and readability.
Features
Registration Check: Verifies the registration status of a domain.
IP Geolocation: Maps domain to IP and retrieves ASN and location data.
Reverse IP: Discovers other domains hosted on the same IP address.
DNS Records: Full dump of the target's DNS records.
WHOIS & Historical WHOIS: Retrieves current and historical registrar data.
SSL Certificates (crt.sh): Subdomain extraction and transparency certificate audit.
Domain Reputation: Risk indicator analysis.
Data Export: Saves results to a JSON file for further analysis.
Installation (Arch Linux)
It is recommended to use a Python virtual environment (venv) to keep your system clean (following PEP 668 in Arch Linux).

# Clone / download files to a directory
mkdir -p ~/cssltd_webosint && cd ~/cssltd_webosint

# Create and activate venv
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

ConfigurationEdit the config.json file in the root directory and add your API keys. If an API key is missing, the tool will use a free alternative (if available) or skip the module.
{
  "WHOIS_XML_API_KEY": "your_key_here",
  "HACKERTARGET_API_KEY": "your_key_here",
  "WHOIS_FREAKS_API_KEY": "your_key_here"
}
UsageThe tool uses command-line flags for individual modules. 
Use the --all flag to run a full scan.

# Help and available options
python cssltd_webosint.py -h

# Quick IP and geolocation scan
python cssltd_webosint.py -d example.com --ip

# Only subdomain scanning based on SSL certificates
python cssltd_webosint.py -d example.com --subdomains

# Full recon with results saved to a JSON file
python cssltd_webosint.py -d example.com --all -o output_example.json
# CSSLTD-WebOSINT
