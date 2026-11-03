import os
import requests

def locate_subdomains(domain, wordlist_file):
    print(f"Scanning target domain: {domain}\n")
    
    if not os.path.exists(wordlist_file):
        print(f"Error: Missing wordlist file -> {wordlist_file}")
        return

    with open(wordlist_file, "r") as stream:
        prefixes = stream.read().splitlines()

    live_hosts = []

    for prefix in prefixes:
        target_url = f"http://{prefix}.{domain}"
        
        try:
            res = requests.get(target_url, timeout=2)
            
            if res.status_code:
                print(f"Found active host: {target_url} | HTTP {res.status_code}")
                live_hosts.append(target_url)
                
        except requests.ConnectionError:
            pass
        except requests.Timeout:
            pass

    print("\nScan operations finished.")
    print(f"Total active hosts identified: {len(live_hosts)}")

if __name__ == "__main__":
    target_host = input("Enter the target domain to scan (e.g., google.com): ")
    list_path = "subdomains.txt"
    
    locate_subdomains(target_host, list_path)
