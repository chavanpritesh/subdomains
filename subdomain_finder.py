import os
import requests

def scan_target_host(domain, wordlist_file):
    print(f"[!] Initiating security enumeration framework for: {domain}")
    
    if not os.path.exists(wordlist_file):
        print(f"[X] Critical Resource Error: Target file '{wordlist_file}' is missing.")
        return

    try:
        with open(wordlist_file, "r", encoding="utf-8") as stream:
            payloads = [line.strip() for line in stream if line.strip()]
    except Exception as error:
        print(f"[X] File Access Exception encountered: {error}")
        return

    print(f"[*] Loaded {len(payloads)} structural variants from lookup table.\n")
    active_records = []
    
    # Realistic browser headers to bypass edge security & WAF tracking
    browser_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }

    for prefix in payloads:
        base_address = f"{prefix}.{domain}"
        
        # Test standard secure layer first, fallback to unencrypted protocol
        for protocol in ["https", "http"]:
            target_endpoint = f"{protocol}://{base_address}"
            
            try:
                # 3-second connection timeout, 5-second read timeout for global networks
                response = requests.get(
                    target_endpoint, 
                    headers=browser_headers, 
                    timeout=(3.0, 5.0), 
                    allow_redirects=True
                )
                
                # Flag anything that isn't a dead connection or bad gateway route
                if response.status_code < 400 or response.status_code == 403:
                    print(f"[+] Active Endpoint Discovered: {target_endpoint} [Status: {response.status_code}]")
                    active_records.append({
                        "url": target_endpoint,
                        "status": response.status_code
                    })
                    break # Stop testing HTTP if HTTPS successfully answered
                    
            except requests.exceptions.SSLError:
                # Domain exists but has an invalid/expired SSL certificate
                print(f"[!] Certificate Alert: {target_endpoint} exists but failed SSL validation.")
                active_records.append({
                    "url": target_endpoint,
                    "status": "SSL_ERROR"
                })
                break
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                continue
            except requests.exceptions.RequestException:
                continue

    print("\n[!] Enumeration cycle completed cleanly.")
    print(f"[#] Verified active deployment vectors: {len(active_records)}")
    return active_records

if __name__ == "__main__":
    requested_domain = input("Provide target host domain (e.g., github.com): ").strip().lower()
    
    # Basic data scrubbing to remove prefixes if pasted by mistake
    if requested_domain.startswith("http://"):
        requested_domain = requested_domain.replace("http://", "")
    elif requested_domain.startswith("https://"):
        requested_domain = requested_domain.replace("https://", "")
        
    lookup_source = "subdomains.txt"
    scan_target_host(requested_domain, lookup_source)
