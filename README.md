# 🔐 IP Intel Pro

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/ip-intel-pro/graphs/commit-activity)

**IP Intel Pro** is a comprehensive IP reputation analysis tool that aggregates threat intelligence data from multiple trusted sources to provide detailed security assessments of IP addresses. Perfect for security analysts, network administrators, and cybersecurity professionals who need quick, reliable IP reputation checks.

![IP Intel Pro Banner](https://via.placeholder.com/800x200/2c2c2c/ffffff?text=IP+Intel+Pro+%7C+Security+Intelligence+%26+Threat+Analysis)

---

## 📋 Table of Contents

- [Features](#-features)
- [Supported Reputation Engines](#-supported-reputation-engines)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Output](#-output)
- [Report Features](#-report-features)
- [Project Structure](#-project-structure)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)
- [Author](#-author)

---

## ✨ Features

- 🔍 **Multi-Source Intelligence**: Queries three leading threat intelligence platforms simultaneously
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

Each engine provides unique insights:
- **VirusTotal**: Community scores, vendor-specific detections, historical analysis
- **MetaDefender**: Sandbox analysis, offline reputation, geo-location data
- **AbuseIPDB**: Abuse confidence scores, ISP information, report history

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

---

## 🚀 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/ip-intel-pro.git
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
VERSION = 1.1.0
AUTHOR = Your Name
YEAR = 2025
COMPANY_NAME = Your Company Name

[VirusTotal]
API_KEY = your_virustotal_api_key_here
ENDPOINT_URL = https://www.virustotal.com/api/v3/urls/
REPORT_LINK = https://www.virustotal.com/gui/url/
FILE_NAME = virus_total_report
REPORT_TITLE = VirusTotal Analysis Report
REPORT_SUB_TITLE = VirusTotal API v3

[MetaDefender]
API_KEY = your_metadefender_api_key_here
ENDPOINT_URL = https://api.metadefender.com/v4/ip/
FILE_NAME = metadefender_report
REPORT_TITLE = MetaDefender Analysis Report
REPORT_SUB_TITLE = MetaDefender API

[AbuseIPDB]
API_KEY = your_abuseipdb_api_key_here
ENDPOINT_URL = https://api.abuseipdb.com/api/v2/check
FILE_NAME = abuseIpDB_report
REPORT_TITLE = AbuseIPDB Analysis Report
REPORT_SUB_TITLE = AbuseIPDB API v2
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
  -s SINGLE_ENTRY, --single-entry SINGLE_ENTRY
                        Single IP address for analysis
  -i IP_LIST, --ip-list IP_LIST
                        File containing list of IP addresses (one per line)
  -V, --version         Show program version
```

---

## 📊 Output

IP Intel Pro generates three types of output files in the `output/` directory:

### 1. Consolidated HTML Report
- **Filename**: `Consolidated_IP_Reputation_Report_[timestamp].html`
- **Contains**: Complete analysis from all three engines in a single file
- **Features**: Color-coded threat levels, professional design, responsive layout

### 2. PDF Report
- **Filename**: `Consolidated_IP_Reputation_Report_[timestamp].pdf`
- **Contains**: Same content as HTML but in PDF format for easy sharing
- **Features**: Print-ready, professional formatting

### 3. CSV Summary
- **Filename**: `Final_Summary_[timestamp].csv`
- **Contains**: Tabular data with scores from all engines
- **Columns**: IP Address, VirusTotal Score, AbuseIPDB Score, MetaDefender Score, Geo Info

### Example Output Structure

```
output/
├── IP_Intel_Report_13Dec2025_10-32-42.html
├── IP_Intel_Report_13Dec2025_10-32-42.pdf
└── Final_Summary_1734528564.csv
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
   - Sandbox analysis (if available)
5. **AbuseIPDB Analysis**:
   - Abuse confidence score
   - ISP and hosting information
   - Report history and statistics
6. **Footer**: Tool version and developer information

---

## 📁 Project Structure

```
ip-intel-pro/
│
├── api/
│   ├── engine.py                    # Main orchestration engine
│   ├── virus_total_engine.py        # VirusTotal API integration
│   ├── metadefender_engine.py       # MetaDefender API integration
│   └── abuseIpDB_engine.py          # AbuseIPDB API integration
│
├── config/
│   └── config.ini                   # Configuration file (API keys)
│
├── utils/
│   ├── config_util.py               # Configuration loader
│   ├── csv_util.py                  # CSV generation utility
│   └── html_util.py                 # HTML/PDF report generator
│
├── output/                          # Generated reports (auto-created)
│
├── main.py                          # Main entry point
├── requirements.txt                 # Python dependencies
└── README.md                        # This file
```

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

---

## 📦 Dependencies

IP Intel Pro requires the following Python packages:

```
aiohttp>=3.9.0
pandas>=2.0.0
pdfkit>=1.0.0
colorama>=0.4.6
asyncio>=3.4.3
```

Install all dependencies:
```bash
pip install -r requirements.txt
```

---

## 🔐 Security Considerations

- **API Keys**: Never commit `config.ini` with real API keys to version control
- **Data Privacy**: IP addresses analyzed may be logged by third-party services
- **Rate Limits**: Respect API rate limits to avoid account suspension
- **Local Storage**: Reports contain sensitive threat intelligence data - store securely

### Best Practices

1. Add `config/config.ini` to `.gitignore`
2. Use environment variables for API keys in production
3. Regularly rotate API keys
4. Review API provider terms of service
5. Implement access controls on output directory

---

## 🗺️ Roadmap

Future enhancements planned:

- [ ] Additional reputation engines (Shodan, IPVoid, etc.)
- [ ] Web interface for easier access
- [ ] Historical tracking and comparison
- [ ] Custom alert thresholds
- [ ] Integration with SIEM platforms
- [ ] API endpoint for programmatic access
- [ ] Docker containerization
- [ ] Scheduled scanning jobs

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Alien C00de

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👤 Author

**Alien C00de**

- GitHub: [@yourusername](https://github.com/alien-c0de)
- LinkedIn: [Your Profile](https://linkedin.com/in/santosh-susveerkar/)
- Email: alien.c00de@gmail.com

---

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com) for comprehensive threat intelligence
- [MetaDefender](https://metadefender.opswat.com) for multi-engine scanning capabilities
- [AbuseIPDB](https://www.abuseipdb.com) for community-driven abuse reporting
- All contributors and users of IP Intel Pro

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

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/ip-intel-pro&type=Date)](https://star-history.com/#yourusername/ip-intel-pro&Date)

---

<div align="center">

**Made with ❤️ for the cybersecurity community**

[Report Bug](https://github.com/yourusername/ip-intel-pro/issues) · [Request Feature](https://github.com/yourusername/ip-intel-pro/issues) · [Documentation](https://github.com/yourusername/ip-intel-pro/wiki)

</div>
