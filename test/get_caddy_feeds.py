# TESTING! Do not use on live services, even if at home :)
 
import os
import requests

# Define the base URL
BASE_URL = "https://github.com/fabriziosalmi/caddy-feeds/releases/download/latest"

# Define the resources to download
RESOURCES = [
    "ip_blacklist.txt",
    "dns_blacklist.txt",
    "rules.json"
]

# Get the directory where the script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Download each resource
for resource in RESOURCES:
    # Construct the full URL
    url = f"{BASE_URL}/{resource}"
    
    # Extract the filename from the resource
    filename = os.path.basename(resource)
    
    # Download the file
    print(f"Downloading {filename}...")
    response = requests.get(url)
    
    # Check if the request was successful
    if response.status_code == 200:
        # Save the file to the script's directory
        file_path = os.path.join(SCRIPT_DIR, filename)
        with open(file_path, "wb") as file:
            file.write(response.content)
        print(f"Saved {filename} to {SCRIPT_DIR}")
    else:
        print(f"Failed to download {filename}. Status code: {response.status_code}")

print("Download process completed.")
