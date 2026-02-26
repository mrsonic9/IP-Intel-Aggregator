import requests
import json


def check_abuseipdb(api_key, ip_address):
    """
    Check IP reputation using AbuseIPDB API.
    Returns the abuse confidence score.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        abuse_score = data['data']['abuseConfidenceScore']
        return abuse_score
    except Exception as e:
        return None


def check_virustotal(api_key, ip_address):
    """
    Check IP reputation using VirusTotal API.
    Returns the number of malicious detections and total vendors.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    
    headers = {
        'x-apikey': api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        total = sum(stats.values())
        
        return malicious, total
    except Exception as e:
        return None, None


def check_censys(api_key, ip_address):
    """
    Check IP information using Censys API.
    Returns open ports, location, and autonomous system information.
    """
    url = f"https://search.censys.io/api/v2/hosts/{ip_address}"
    
    headers = {
        'Authorization': f'Bearer {api_key}'
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        result = data.get('result', {})
        
        # Extract services (open ports)
        services = result.get('services', [])
        open_ports = []
        for service in services:
            port = service.get('port')
            service_name = service.get('service_name', 'Unknown')
            open_ports.append(f"{port}/{service_name}")
        
        # Extract location
        location = result.get('location', {})
        city = location.get('city', 'Unknown')
        country = location.get('country', 'Unknown')
        
        # Extract autonomous system
        asn_info = result.get('autonomous_system', {})
        asn_name = asn_info.get('name', 'Unknown')
        
        return open_ports, city, country, asn_name
    except Exception as e:
        return None, None, None, None


def determine_threat_level(abuse_score, vt_malicious):
    """
    Determine if the IP is malicious based on the results.
    """
    if abuse_score is None and vt_malicious is None:
        return "UNKNOWN"
    
    if (abuse_score and abuse_score >= 50) or (vt_malicious and vt_malicious > 10):
        return "MALICIOUS"
    elif (abuse_score and abuse_score >= 25) or (vt_malicious and vt_malicious > 5):
        return "SUSPICIOUS"
    else:
        return "CLEAN"


def main():
    """
    Main function to run the IP-Intel Tool.
    """
    print("--- IP-Intel Tool ---")
    
    # Get user inputs
    abuseipdb_key = input("Please enter your AbuseIPDB API Key: ")
    virustotal_key = input("Please enter your VirusTotal API Key: ")
    censys_key = input("Please enter your Censys API Key: ")
    print()
    target_ip = input("Target IP: ")
    print()
    
    # Check AbuseIPDB
    print("[+] Checking AbuseIPDB...")
    abuse_score = check_abuseipdb(abuseipdb_key, target_ip)
    
    if abuse_score is not None:
        if abuse_score >= 75:
            risk_level = "High Risk"
        elif abuse_score >= 50:
            risk_level = "Medium Risk"
        elif abuse_score >= 25:
            risk_level = "Low Risk"
        else:
            risk_level = "Clean"
        print(f"    Score: {abuse_score}% ({risk_level})")
    else:
        print("    Error: Could not retrieve data from AbuseIPDB")
    
    # Check VirusTotal
    print("[+] Checking VirusTotal...")
    vt_malicious, vt_total = check_virustotal(virustotal_key, target_ip)
    
    if vt_malicious is not None:
        print(f"    Result: {vt_malicious}/{vt_total} vendors flagged as malicious.")
    else:
        print("    Error: Could not retrieve data from VirusTotal")
    
    # Check Censys
    print("[+] Checking Censys...")
    open_ports, city, country, asn_name = check_censys(censys_key, target_ip)
    
    if open_ports is not None:
        ports_display = ", ".join(open_ports) if open_ports else "No open ports detected"
        print(f"    Open Ports: {ports_display}")
        print(f"    Location: {city}, {country}")
        print(f"    Network Owner: {asn_name}")
    else:
        print("    Error: Could not retrieve data from Censys")
    
    print()
    
    # Final conclusion
    threat_level = determine_threat_level(abuse_score, vt_malicious)
    print(f"Conclusion: This IP is {threat_level}.")


if __name__ == "__main__":
    main()
