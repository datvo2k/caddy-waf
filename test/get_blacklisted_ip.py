import requests
import re
import ipaddress
from tqdm import tqdm

# List of blocklist URLs and expected line formats
blocklist_sources = {
    "Emerging Threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "CI Army List": "http://cinsscore.com/list/ci-badguys.txt",
    "IPsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
    "BlockList.de": "https://www.blocklist.de/lists/all.txt",
    "Blocklist.de - SSH": "https://www.blocklist.de/lists/ssh.txt",
    "Greensnow": "https://blocklist.greensnow.co/greensnow.txt",
}

# --- Tor Exit Node Source (Testing) ---
tor_exit_nodes_url = "https://check.torproject.org/exit-addresses" # Testing


def extract_ips(source_name, url):
    """Fetches data from the given URL and extracts IP addresses."""
    ips = set()
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        content = response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {source_name} from {url}: {e}")
        return ips

    if source_name == "Talos Intelligence":
        print(f"Skipping {source_name} due to webpage format, needs manual parsing.")
        return ips
    elif source_name == "TOR Exit Nodes":
        for line in content.splitlines():
            if line.startswith("ExitAddress"):
                parts = line.split(" ")
                if len(parts) > 1:
                    try:
                        ipaddress.ip_address(parts[1].strip())
                        ips.add(parts[1].strip())
                    except ValueError:
                        continue
        return ips
    elif source_name == "Spamhaus DROP" or source_name == "Spamhaus EDROP":
        for line in content.splitlines():
           line = line.strip()
           if not line or line.startswith(";"):
                continue
           if "/" in line:
               try:
                    for ip in ipaddress.ip_network(line, strict=False):
                        ips.add(str(ip))
               except ValueError:
                    continue
           else:
                try:
                   ipaddress.ip_address(line)
                   ips.add(line)
                except ValueError:
                   continue
        return ips
    elif source_name == "MaxMind GeoIP2 Anonymous IP Database":
        # Requires a license key, skipping for now.
        print(f"Skipping {source_name} because it requires a license key.")
        return ips
    else:
        # Default parsing for normal text file blocklists
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Normalize ranges to single IPs
            if "/" in line:
                try:
                    for ip in ipaddress.ip_network(line, strict=False):
                        ips.add(str(ip))
                except ValueError:
                    continue
            elif "-" in line:
                try:
                    start, end = line.split('-')
                    start_ip = ipaddress.ip_address(start.strip())
                    end_ip = ipaddress.ip_address(end.strip())
                    if start_ip.version == end_ip.version:
                        for ip_int in range(int(start_ip), int(end_ip) + 1):
                            ips.add(str(ipaddress.ip_address(ip_int)))
                except ValueError:
                    continue
            else:
                try:
                    ipaddress.ip_address(line)
                    ips.add(line)
                except ValueError:
                    continue
        return ips


def is_valid_ip(ip_str):
    """Helper function to check if an IP address is valid."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def ip_to_int(ip_str):
    """Converts an IP address string to its integer representation."""
    try:
        return int(ipaddress.ip_address(ip_str))
    except ValueError:
        return None

def extract_tor_exit_nodes(url):
    """Fetches data from the given URL and extracts Tor exit node IPs."""
    ips = set()
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Tor exit nodes from {url}: {e}")
        return ips

    for line in content.splitlines():
        if line.startswith("ExitAddress"):
            parts = line.split(" ")
            if len(parts) > 1:
                try:
                    ipaddress.ip_address(parts[1].strip())
                    ips.add(parts[1].strip())
                except ValueError:
                    continue
    return ips


def main():
    combined_ips = set()
    for source_name, url in tqdm(blocklist_sources.items(), desc="Processing Blocklists"):
        print(f"Processing {source_name} from {url}")
        ips = extract_ips(source_name, url)
        print(f"  Found {len(ips)} IPs in {source_name}")
        combined_ips.update(ips)

    # --- Tor Exit Node Processing (Testing) ---
    tor_exit_ips = extract_tor_exit_nodes(tor_exit_nodes_url)
    print(f"Total Tor exit node IPs: {len(tor_exit_ips)}")
    valid_tor_ips = [ip for ip in tor_exit_ips if is_valid_ip(ip)]
    print(f"Total Valid Tor IPs after filtering: {len(valid_tor_ips)}")

    # Add Tor exit IPs to the combined IPs
    combined_ips.update(valid_tor_ips)

    print(f"Total IPs before filtering and deduplication: {len(combined_ips)}")

    # Filter out invalid IPs before sorting.
    valid_ips = [ip for ip in combined_ips if is_valid_ip(ip)]
    print(f"Total Valid IPs after filtering: {len(valid_ips)}")

    # Remove duplicates by converting to a set before sorting
    unique_ips = set(valid_ips)

    with open("ip_blacklist.txt", "w") as f:
        # Sort using the integer representation and write each IP to the file
        for ip in sorted(unique_ips, key=ip_to_int):
            f.write(f"{ip}\n")

    print("IP blacklist saved to ip_blacklist.txt")


if __name__ == "__main__":
    main()
