import getpass
import requests


def check_abuseipdb(api_key, ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        if not response.ok:
            return None, f"API error: {response.status_code}"
        data = response.json()
        score = data.get("data", {}).get("abuseConfidenceScore", None)
        if score is None:
            return None, "No data returned"
        if score >= 75:
            risk = "High Risk"
        elif score >= 50:
            risk = "Medium Risk"
        elif score >= 25:
            risk = "Low Risk"
        else:
            risk = "Clean"
        return score, risk
    except Exception as e:
        return None, f"Error: {e}"


def check_virustotal(api_key, ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": api_key,
    }
    try:
        response = requests.get(url, headers=headers)
        if not response.ok:
            return None, f"API error: {response.status_code}"
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) if stats else 0
        return malicious, total
    except Exception as e:
        return None, f"Error: {e}"


def check_censys(api_key, ip_address):
    url = f"https://search.censys.io/api/v2/hosts/{ip_address}"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }
    try:
        response = requests.get(url, headers=headers)
        if not response.ok:
            return None, "Unknown", f"API error: {response.status_code}"
        data = response.json()
        result = data.get("result", {})

        services = result.get("services", [])
        ports = []
        for svc in services:
            port = svc.get("port", "")
            transport = svc.get("transport_protocol", "")
            service_name = svc.get("service_name", "")
            if service_name:
                ports.append(f"{port}/{service_name}")
            elif port:
                ports.append(str(port))

        location = result.get("location", {})
        city = location.get("city", "")
        country = location.get("country", "")
        location_str = ", ".join(filter(None, [city, country])) or "Unknown"

        asn = result.get("autonomous_system", {})
        network_owner = asn.get("name", "Unknown")

        return ports, location_str, network_owner
    except Exception as e:
        return None, "Unknown", f"Error: {e}"


def determine_threat_level(abuse_score, vt_malicious):
    if abuse_score is None and vt_malicious is None:
        return "UNKNOWN"
    score = abuse_score if abuse_score is not None else 0
    malicious = vt_malicious if vt_malicious is not None else 0
    if score >= 50 or malicious >= 10:
        return "MALICIOUS"
    if score >= 25 or malicious >= 5:
        return "SUSPICIOUS"
    return "CLEAN"


def main():
    print("--- IP-Intel Tool ---")
    abuse_key = getpass.getpass("Please enter your AbuseIPDB API Key: ").strip()
    vt_key = getpass.getpass("Please enter your VirusTotal API Key: ").strip()
    censys_key = getpass.getpass("Please enter your Censys API Key: ").strip()
    ip_address = input("\nPlease enter the target IP address: ").strip()

    print(f"\nTarget IP: {ip_address}")

    print("[+] Checking AbuseIPDB...")
    abuse_score, abuse_risk = check_abuseipdb(abuse_key, ip_address)
    if abuse_score is not None:
        print(f"    Score: {abuse_score}% ({abuse_risk})")
    else:
        print(f"    {abuse_risk}")

    print("[+] Checking VirusTotal...")
    vt_malicious, vt_total = check_virustotal(vt_key, ip_address)
    if vt_malicious is not None and isinstance(vt_total, int):
        print(f"    Result: {vt_malicious}/{vt_total} vendors flagged as malicious.")
    else:
        print(f"    {vt_total}")

    print("[+] Checking Censys...")
    ports, location_str, network_owner = check_censys(censys_key, ip_address)
    if ports is not None:
        ports_display = ", ".join(ports) if ports else "None detected"
        print(f"    Open Ports: {ports_display}")
        print(f"    Location: {location_str}")
        print(f"    Network Owner: {network_owner}")
    else:
        print(f"    {network_owner}")

    threat_level = determine_threat_level(
        abuse_score,
        vt_malicious if isinstance(vt_malicious, int) else None,
    )
    print(f"\nConclusion: This IP is {threat_level}.")


if __name__ == "__main__":
    main()
