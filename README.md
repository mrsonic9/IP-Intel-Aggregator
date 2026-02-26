# IP-Intel Tool 🔍

A professional Security Operations Center (SOC) tool for checking IP address reputation using multiple threat intelligence APIs.

---

## 📚 Libraries Used

### External Libraries
- **`requests`** - HTTP library for making API calls to external services
  - Used to communicate with AbuseIPDB, VirusTotal, and Censys APIs
  - Handles HTTP GET requests and response processing
  - Includes HTTPBasicAuth for Censys authentication

### Built-in Python Libraries
- **`json`** - Native Python library for handling JSON data
  - Parses API responses from threat intelligence services
  - No installation required (comes with Python)

---

## 📋 Requirements

### System Requirements
- **Python 3.6 or higher**
- **Internet connection** (for API calls)
- **Virtual environment** (recommended)

### Python Dependencies
```
requests>=2.32.0
```

### API Keys Required
You need to obtain free API keys from:

1. **AbuseIPDB** - https://www.abuseipdb.com/register
   - Sign up for a free account
   - Navigate to your account settings
   - Copy your API key

2. **VirusTotal** - https://www.virustotal.com/gui/join-us
   - Create a free account
   - Go to your profile
   - Copy your API key from the API Key section

3. **Censys** - https://censys.io/register
   - Sign up for a free account
   - Go to Account Settings → API
   - Copy your **API Key**

---

## 🚀 Installation

### Step 1: Clone or Download the Project
```bash
cd "/path/to/your/Projects/IP intel"
```

### Step 2: Create Virtual Environment
```bash
python3 -m venv ip_intel_project
```

### Step 3: Activate Virtual Environment

**On Linux/Mac:**
```bash
source ip_intel_project/bin/activate
```

**On Windows:**
```bash
ip_intel_project\Scripts\activate
```

### Step 4: Install Dependencies
```bash
pip install requests
```

Or use requirements file (if created):
```bash
pip install -r requirements.txt
```

---

## 💻 Usage

### Run the Tool
```bash
python ip_intel.py
```

### Interactive Prompts
The tool will ask you for:
1. Your **AbuseIPDB API Key**
2. Your **VirusTotal API Key**
3. Your **Censys API Key**
4. The **IP address** you want to investigate

### Example Output
```
--- IP-Intel Tool ---
Please enter your AbuseIPDB API Key: ************
Please enter your VirusTotal API Key: ************
Please enter your Censys API Key: ************

Target IP: 1.2.3.4
[+] Checking AbuseIPDB...
    Score: 100% (High Risk)
[+] Checking VirusTotal...
    Result: 65/90 vendors flagged as malicious.
[+] Checking Censys...
    Open Ports: 22/SSH, 80/HTTP, 443/HTTPS
    Location: Mountain View, United States
    Network Owner: Google LLC
    
Conclusion: This IP is MALICIOUS.
```

---

## 🏗️ Code Structure

The script follows a **modular design** with separate functions for each task:

### Functions

1. **`check_abuseipdb(api_key, ip_address)`**
   - Queries AbuseIPDB API
   - Returns abuse confidence score (0-100%)
   - Uses 90-day historical data

2. **`check_virustotal(api_key, ip_address)`**
   - Queries VirusTotal API
   - Returns malicious detection count and total vendors
   - Analyzes last_analysis_stats from response

3. **`check_censys(api_key, ip_address)`**
   - Queries Censys API for network information
   - Returns open ports with service names
   - Returns location (city and country)
   - Returns autonomous system (network owner) information
   - Uses Bearer Token authentication

4. **`determine_threat_level(abuse_score, vt_malicious)`**
   - Evaluates threat based on API results
   - Returns: MALICIOUS, SUSPICIOUS, CLEAN, or UNKNOWN

5. **`main()`**
   - Orchestrates the entire workflow
   - Handles user input for all three APIs
   - Displays formatted results from all sources

---

## 📊 Threat Level Classification

### AbuseIPDB Score Interpretation
- **75-100%** → High Risk
- **50-74%** → Medium Risk
- **25-49%** → Low Risk
- **0-24%** → Clean

### Final Conclusion Logic
- **MALICIOUS**: Abuse score ≥ 50% OR 10+ malicious vendors
- **SUSPICIOUS**: Abuse score ≥ 25% OR 5+ malicious vendors
- **CLEAN**: Below suspicious thresholds
- **UNKNOWN**: API errors or no data available

---

## 🔐 API Documentation

### AbuseIPDB API
- **Endpoint**: `https://api.abuseipdb.com/api/v2/check`
- **Method**: GET
- **Headers**: 
  - `Key`: Your API key
  - `Accept`: application/json
- **Parameters**:
  - `ipAddress`: Target IP
  - `maxAgeInDays`: 90 (checks last 90 days)

### VirusTotal API
- **Endpoint**: `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
- **Method**: GET
- **Headers**:
  - `x-apikey`: Your API key
- **Response Path**: `data → attributes → last_analysis_stats`

### Censys API
- **Endpoint**: `https://search.censys.io/api/v2/hosts/{ip}`
- **Method**: GET
- **Authentication**: Bearer Token
  - Header: `Authorization: Bearer {your_api_key}`
- **Response Data Extracted**:
  - `result.services`: Array of open ports and service names
  - `result.location.city` & `result.location.country`: Geographic location
  - `result.autonomous_system.name`: Network owner/provider information

---

## 🛠️ Troubleshooting

### Common Issues

**Issue**: `ModuleNotFoundError: No module named 'requests'`
- **Solution**: Ensure virtual environment is activated and run `pip install requests`

**Issue**: API returns errors
- **Solution**: 
  - Verify your API keys are correct
  - Check if you've exceeded your API rate limits
  - Ensure you have internet connectivity

**Issue**: Virtual environment not activating
- **Solution**: 
  - Linux: Install python3-venv: `sudo apt install python3-venv`
  - Windows: Reinstall Python with "pip" option checked

---

## 📝 Notes

- **Rate Limits**: Free tier APIs have request limits (check provider documentation)
- **Privacy**: Never share your API keys publicly
- **Accuracy**: Results depend on threat intelligence database updates
- **Use Case**: Suitable for SOC analysts, network administrators, and security researchers

---

## 👨‍💻 Author

Created as a professional SOC tool for IP reputation checking.

---

## 📄 License

Free to use for educational and professional security analysis purposes.
