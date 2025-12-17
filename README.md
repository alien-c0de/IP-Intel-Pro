# 🔐 IP Intel Pro V2.0

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/alien-c0de/ip-intel-pro/graphs/commit-activity)

**IP Intel Pro** is a comprehensive IP reputation analysis tool that aggregates threat intelligence data from multiple trusted sources to provide detailed security assessments of IP addresses. Perfect for security analysts, network administrators, and cybersecurity professionals who need quick, reliable IP reputation checks.

![IP Intel Pro Banner](https://via.placeholder.com/800x200/2c2c2c/ffffff?text=IP+Intel+Pro+%7C+Security+Intelligence+%26+Threat+Analysis)

---

## 📋 Table of Contents

- [Features](#-features)
- [Supported Reputation Engines](#-supported-reputation-engines)
- [Prerequisites](#-prerequisites)
- [Screenshots](#-screenshots)
- [Installation](#-installation)
- [Configuration](#%EF%B8%8F-configuration)
- [Usage](#-usage)
- [Output](#-output)
- [Report Features](#-report-features)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#%EF%B8%8F-roadmap)
- [License](#-license)
- [Author](#-author)
- [Acknowledgments](#-acknowledgments)
- [Support](#-support)
- [Star History](#-star-history)

---

## ✨ Features

- 🔍 **Multi-Source Intelligence**: Queries seven leading threat intelligence platforms simultaneously
- 📊 **Consolidated Reporting**: Single comprehensive report combining all sources
- 🎨 **Professional Reports**: Generates HTML and PDF reports with modern, clean design
- 📈 **CSV Export**: Exports summary data in CSV format for further analysis
- ⚡ **Async Performance**: Fast concurrent API calls for efficient processing
- 📦 **Bulk Analysis**: Support for single IP or bulk IP address scanning
- 🎯 **Color-Coded Results**: Visual threat level indicators (red for malicious, orange for suspicious, green for clean)
- 🔒 **Secure**: API keys stored in configuration file (not hardcoded)
- 🖥️ **Cross-Platform**: Works on Windows, Linux, and macOS

---

## 🌐 Supported Reputation Engines

IP Intel Pro integrates with the following threat intelligence platforms:

| Engine | Website | Purpose |
|--------|---------|---------|
| **VirusTotal** | [virustotal.com](https://www.virustotal.com) | Comprehensive threat detection using 90+ security vendors |
| **MetaDefender** | [metadefender.opswat.com](https://metadefender.opswat.com) | Multi-scanning with geo-location intelligence |
| **AbuseIPDB** | [abuseipdb.com](https://www.abuseipdb.com) | Community-driven IP abuse reporting database |
| **AlienVault OTX** | [otx.alienvault.com](https://otx.alienvault.com) | The world's largest open threat intelligence community |
| **GreyNoise** | [greynoise.io](https://www.greynoise.io) | Internet background noise analysis and scanner detection |
| **IPQualityScore** | [ipqualityscore.com](https://www.ipqualityscore.com) | Enterprise-grade fraud protection and IP risk scoring |
| **Cisco Talos** | [talosintelligence.com](https://talosintelligence.com) | Cisco's threat intelligence and research platform |

---

## 📋 Prerequisites

Before installing IP Intel Pro, ensure you have:

- **Python 3.8 or higher**
- **pip** (Python package manager)
- **wkhtmltopdf** (for PDF generation)
  - Windows: Download from [wkhtmltopdf.org](https://wkhtmltopdf.org/downloads.html)
  - Linux: `sudo apt-get install wkhtmltopdf`
  - macOS: `brew install wkhtmltopdf`

### API Keys Required

You'll need free API keys from:
1. **VirusTotal**: [Sign up here](https://www.virustotal.com/gui/join-us)
2. **MetaDefender**: [Get API key](https://metadefender.opswat.com/sign-up)
3. **AbuseIPDB**: [Register here](https://www.abuseipdb.com/register)
4. **AlienVault OTX**: [Register here](https://otx.alienvault.com/sign-up)
5. **GreyNoise**: [Get Community API](https://viz.greynoise.io/signup)
6. **IPQualityScore**: [Create account](https://www.ipqualityscore.com/create-account)

**Note**: Cisco Talos does not require an API key.

---

## 📸 Screenshots

### Terminal Input
![IpIntelPro](https://github.com/user-attachments/assets/c2d59121-9926-4fe4-a03b-0d24118219d8)

*Command-line interface showing the analysis in progress*

### HTML Report
![Ip Report](https://github.com/user-attachments/assets/62bd8bc8-b1ed-451a-b9b0-780e1bfc74f7)

*Professional report with color-coded threat levels*

---

## 🚀 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/alien-c0de/ip-intel-pro.git
cd ip-intel-pro
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Install wkhtmltopdf

**Windows:**
```bash
# Download installer from https://wkhtmltopdf.org/downloads.html
# Install to: C:\Program Files\wkhtmltopdf\
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install wkhtmltopdf
```

**macOS:**
```bash
brew install wkhtmltopdf
```

---

## ⚙️ Configuration

### Step 1: Configure API Keys

Edit the `config/config.ini` file with your API keys:

```ini
[General]
AUTHOR = Alien C00de
YEAR = 2025
VERSION = 1.3.0
COMPANY_NAME = Alien Security
TOOL_NAME = IP Intel Pro
EMAIL = alien.c00de@gmail.com

[VirusTotal]
API_KEY = Your_VirusTotal_API_Key
ENDPOINT_URL = https://www.virustotal.com/api/v3/urls/
REPORT_LINK = https://www.virustotal.com/gui/url/

[MetaDefender]
API_KEY = Your_MetaDefender_API_Key
ENDPOINT_URL = https://api.metadefender.com/v4/ip/

[AbuseIPDB]
API_KEY = Your_AbuseIPDB_API_Key
ENDPOINT_URL = https://api.abuseipdb.com/api/v2/check

[AlienVault_OTX]
API_KEY = Your_AlienVault_API_Key
ENDPOINT_URL = https://otx.alienvault.com/api/v1/indicators/IPv4/

[GreyNoise]
API_KEY = Your_GreyNoise_API_Key
ENDPOINT_URL = https://api.greynoise.io/v3/community/

[IPQualityScore]
API_KEY = Your_IPQualityScore_API_Key
ENDPOINT_URL = https://ipqualityscore.com/api/json/ip/

[CISCO_Talos]
ENDPOINT_URL = https://talosintelligence.com/sb_api/query_lookup
REFERER = https://talosintelligence.com/reputation_center/lookup?search=
```

### Step 2: Customize Company Branding (Optional)

Update the `COMPANY_NAME` in the `[General]` section to display your organization's name in reports.

---

## 💻 Usage

### Analyze Single IP Address

```bash
python main.py -s 8.8.8.8
```

### Analyze Multiple IP Addresses (Bulk Mode)

Create a text file with one IP per line:

**ip_list.txt:**
```
8.8.8.8
1.1.1.1
208.67.222.222
```

Run the analysis:
```bash
python main.py -i ip_list.txt
```

### Show Version

```bash
python main.py -V
```

### Command-Line Options

```bash
usage: main.py [-h] [-s SINGLE_ENTRY] [-i IP_LIST] [-V]

IP Intel Pro: Comprehensive IP Reputation Analysis

optional arguments:
  -h, --help            Show this help message and exit
  -s SINGLE_ENTRY       Single IP address for analysis
  -i IP_LIST            File containing list of IP addresses (one per line)
  -V, --version         Show program version
```

---

## 📊 Output

IP Intel Pro generates three types of output files in the `output/` directory:

### 1. Consolidated HTML Report
- **Filename**: `IP_Intel_Report_[timestamp].html`
- **Contains**: Complete analysis from all seven engines in a single file
- **Features**: Color-coded threat levels, professional design, responsive layout

### 2. PDF Report
- **Filename**: `IP_Intel_Report_[timestamp].pdf`
- **Contains**: Same content as HTML but in PDF format for easy sharing
- **Features**: Print-ready, professional formatting

### 3. CSV Summary
- **Filename**: `Final_Summary_[timestamp].csv`
- **Contains**: Tabular data with scores from all engines
- **Columns**: 
  - IP Address
  - VirusTotal Malicious Score
  - AbuseIPDB Confidence Score
  - MetaDefender Score & Geo Info
  - AlienVault Reputation Score
  - GreyNoise Classification & Service Name
  - IPQualityScore Fraud Score & ISP
  - Cisco Talos Reputation & Category

### Example Output Structure

```
output/
├── IP_Intel_Report_17Dec2025_14-32-42.html
├── IP_Intel_Report_17Dec2025_14-32-42.pdf
└── Final_Summary_17Dec2025_14-32-42.csv
```

---

## 🎨 Report Features

### Visual Threat Indicators

Reports use color-coded indicators for quick threat assessment:

| Threat Level | Color | Description |
|--------------|-------|-------------|
| **MALICIOUS** | 🔴 Red | Confirmed malicious activity detected |
| **SUSPICIOUS** | 🟠 Orange | Suspicious behavior identified |
| **CLEAN/HARMLESS** | 🟢 Green | No threats detected |
| **UNDETECTED** | ⚪ Gray | Not flagged by security vendors |

### Report Sections

Each consolidated report includes:

1. **Header**: Company branding and report metadata
2. **Timestamp**: Generation date and time
3. **VirusTotal Analysis**: 
   - Community score (malicious/total vendors)
   - Detailed vendor-specific results
   - Crowdsourced threat context
4. **MetaDefender Analysis**:
   - Multi-engine scanning results
   - Geo-location information
   - Security vendor detections
5. **AbuseIPDB Analysis**:
   - Abuse confidence score
   - ISP and hosting information
   - Report history and statistics
6. **AlienVault OTX Analysis**:
   - Reputation score and risk level
   - Threat pulses and community intelligence
   - Geographic and network information
7. **GreyNoise Analysis**:
   - Noise classification (Internet background noise)
   - RIOT (Common Business Service) verification
   - Service name and activity classification
8. **IPQualityScore Analysis**:
   - Fraud score and risk rating
   - VPN, Proxy, and Tor node detection
   - Bot status and connection type
9. **Cisco Talos Intelligence Analysis**:
   - Reputation score and category
   - Threat intelligence and email reputation
   - Network ownership information
10. **Footer**: Tool version and developer information

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. PDF Generation Fails

**Error:** `[!] PDF generation failed`

**Solution:**
- Ensure wkhtmltopdf is installed
- Windows: Check installation path is `C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe`
- Linux/macOS: Verify installation with `which wkhtmltopdf`
- HTML report will still be generated successfully

#### 2. API Rate Limit Exceeded

**Error:** `Error Code: 429` or `Quota exceeded`

**Solution:**
- Wait before making additional requests
- Consider upgrading to premium API plans for higher limits
- For bulk analysis, add delays between batches

#### 3. Missing API Keys

**Error:** `API key not found`

**Solution:**
- Verify API keys are correctly added to `config/config.ini`
- Ensure no extra spaces before or after the API key
- Check that you're using valid, active API keys

#### 4. Network/Connection Errors

**Error:** `Connection timeout` or `Unable to connect`

**Solution:**
- Check your internet connection
- Verify firewall settings allow outbound connections
- Ensure API endpoints are accessible from your network

#### 5. Import Errors

**Error:** `ModuleNotFoundError`

**Solution:**
```bash
pip install -r requirements.txt --upgrade
```

#### 6. Mixed Error and Success Results in CSV

**Issue:** Some IPs show errors while others succeed, but CSV doesn't include all results

**Solution:**
- Updated CSV utility now handles mixed results properly
- All IPs will appear in the CSV with either data or error messages
- Check the CSV file - it should contain all scanned IPs

---

## 🗺️ Roadmap

Future enhancements planned:

- [ ] Additional reputation engines (Shodan, Censys)
- [ ] Web interface for easier access
- [ ] Scheduled scanning jobs
- [ ] REST API for integration
- [ ] Docker containerization
- [ ] Real-time threat feed integration
- [ ] Historical data tracking and trending

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Alien C00de**

- GitHub: [@alien-c0de](https://github.com/alien-c0de)
- LinkedIn: [santosh-susveerkar](https://linkedin.com/in/santosh-susveerkar/)
- Email: alien.c00de@gmail.com
- Website: [Coming Soon]

---

## 🙏 Acknowledgments

Special thanks to the following threat intelligence platforms for providing APIs:

- [VirusTotal](https://www.virustotal.com) - For comprehensive multi-vendor malware detection
- [MetaDefender](https://metadefender.opswat.com) - For multi-scanning capabilities
- [AbuseIPDB](https://www.abuseipdb.com) - For community-driven abuse reporting
- [AlienVault OTX](https://otx.alienvault.com) - For open threat intelligence
- [GreyNoise](https://www.greynoise.io) - For internet noise analysis
- [IPQualityScore](https://www.ipqualityscore.com) - For fraud detection and risk scoring
- [Cisco Talos](https://talosintelligence.com) - For comprehensive threat intelligence

All contributors and users of IP Intel Pro are also greatly appreciated!

---

## 📞 Support

Need help? Here's how to get support:

1. **Documentation**: Check this README first
2. **Issues**: [Open an issue](https://github.com/alien-c0de/ip-intel-pro/issues) on GitHub
3. **Discussions**: Join [GitHub Discussions](https://github.com/alien-c0de/ip-intel-pro/discussions)
4. **Email**: Contact at alien.c00de@gmail.com

---

## ⭐ Star History

If you find IP Intel Pro useful, please consider giving it a star! ⭐

[![Star History Chart](https://api.star-history.com/svg?repos=alien-c0de/ip-intel-pro&type=Date)](https://star-history.com/#alien-c0de/ip-intel-pro&Date)

---

<div align="center">

**Made with ❤️ for the cybersecurity community**

[Report Bug](https://github.com/alien-c0de/ip-intel-pro/issues) · [Request Feature](https://github.com/alien-c0de/ip-intel-pro/issues) · [Documentation](https://github.com/alien-c0de/ip-intel-pro/wiki)

</div>