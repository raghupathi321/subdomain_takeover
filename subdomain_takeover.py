import requests
import dns.resolver
import argparse

# List of known fingerprints for subdomain takeovers
FINGERPRINTS = {
    "AWS S3": "NoSuchBucket",
    "GitHub Pages": "There isn't a GitHub Pages site here.",
    "Heroku": "No such app",
    "Bitbucket": "Repository not found",
    "GitLab": "The page could not be found or you don't have permission to view it.",
    "Tumblr": "There's nothing here.",
    "Shopify": "Sorry, this shop is currently unavailable.",
    # Add more fingerprints as needed
}

def resolve_subdomain(subdomain):
    """Resolve the subdomain to check if it exists."""
    try:
        answers = dns.resolver.resolve(subdomain, 'A')
        return [answer.to_text() for answer in answers]
    except dns.resolver.NXDOMAIN:
        return None
    except Exception as e:
        print(f"Error resolving subdomain {subdomain}: {e}")
        return None

def check_takeover(subdomain):
    """Check for potential subdomain takeover vulnerabilities."""
    try:
        response = requests.get(f"http://{subdomain}", timeout=10)
        response_text = response.text
        for service, fingerprint in FINGERPRINTS.items():
            if fingerprint in response_text:
                return service
    except requests.exceptions.RequestException as e:
        print(f"Error making request to {subdomain}: {e}")
    return None

def process_subdomains(file_path):
    """Process a list of subdomains from a file."""
    with open(file_path, "r") as file:
        subdomains = [line.strip() for line in file if line.strip()]
    
    for subdomain in subdomains:
        print(f"\nChecking subdomain: {subdomain}")
        
        # Step 1: Resolve the subdomain
        ip_addresses = resolve_subdomain(subdomain)
        if not ip_addresses:
            print(f"The subdomain {subdomain} does not resolve to any IP address.")
            continue
        print(f"Resolved IP addresses for {subdomain}: {', '.join(ip_addresses)}")
        
        # Step 2: Check for subdomain takeover
        vulnerable_service = check_takeover(subdomain)
        if vulnerable_service:
            print(f"[!] Potential subdomain takeover vulnerability detected!")
            print(f"[!] Service: {vulnerable_service}")
        else:
            print(f"No subdomain takeover vulnerability detected for {subdomain}.")

def main():
    parser = argparse.ArgumentParser(description="Test for subdomain takeover vulnerabilities.")
    parser.add_argument("file", help="Path to the file containing subdomains (one per line).")
    args = parser.parse_args()

    process_subdomains(args.file)

if __name__ == "__main__":
    main()

