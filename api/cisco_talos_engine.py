import aiohttp
import asyncio
from colorama import Fore, Style
from utils.config_util import Configuration

class cisco_talos:
    
    def __init__(self) -> None:
        self.config = Configuration()
        self.summary_list = []
        
    async def get_summary_list(self):
        return self.summary_list
    
    async def generate_Report(self, target_url, isFile=False):
        try:
            self.summary_list = []
            ips = []
            
            if isFile:
                with open(target_url, "r") as url_file:
                    for url in url_file.readlines():
                        ips.append(url.strip())
            else:
                ips = list(target_url.split(","))
            
            html_content = []
            
            for ip in ips:
                ip = ip.strip()
                if not ip:
                    continue
                    
                print(Fore.CYAN + Style.BRIGHT + f"[*] Querying Cisco Talos Intelligence for {ip}..." + Fore.RESET)
                
                # Talos uses a specific query format
                query_data = {
                    "query_string": ip,
                    "query_type": "ip",
                    "offset": 0,
                    "order": "ip"
                }
                
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Referer": f"{self.config.TALOS_REFERER}{ip}",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest"
                }
                
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.post(
                            self.config.TALOS_ENDPOINT_URL,
                            data=query_data,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=30)
                        ) as response:
                            
                            if response.status == 200:
                                data = await response.json()
                                
                                if data and isinstance(data, dict):
                                    html_content.append(self._format_html_report(ip, data))
                                    
                                    # Add to summary for CSV
                                    reputation = self._get_reputation(data)
                                    category = self._get_category(data)
                                    self.summary_list.append([reputation, category])
                                else:
                                    html_content.append(self._format_error_html(ip, "No data returned"))
                                    self.summary_list.append(["No Data", "N/A"])
                            else:
                                error_msg = f"HTTP {response.status}"
                                html_content.append(self._format_error_html(ip, error_msg))
                                self.summary_list.append([error_msg, "N/A"])
                                
                    except asyncio.TimeoutError:
                        html_content.append(self._format_error_html(ip, "Request timeout"))
                        self.summary_list.append(["Timeout", "N/A"])
                    except Exception as e:
                        error_msg = str(e)
                        html_content.append(self._format_error_html(ip, error_msg))
                        self.summary_list.append([f"Error: {error_msg}", "N/A"])
            
            return "".join(html_content)
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            print(Fore.RED + Style.BRIGHT + f"[-] Cisco Talos Error: {error_msg}" + Fore.RESET)
            return f"<p style='color: red; margin: 20px;'>Error: {error_msg}</p>"
    
    def _get_reputation(self, data):
        """Extract reputation from Talos response"""
        try:
            if 'reputation' in data:
                return data['reputation']
            elif 'web_reputation' in data:
                return data['web_reputation']
            elif 'email_reputation' in data:
                return data['email_reputation']
            return "Unknown"
        except:
            return "Unknown"
    
    def _get_category(self, data):
        """Extract category from Talos response"""
        try:
            if 'category' in data:
                category = data['category']
                if isinstance(category, dict) and 'description' in category:
                    return category['description']
                return str(category)
            elif 'web_category' in data:
                return data['web_category']
            return "Uncategorized"
        except:
            return "Uncategorized"
    
    def _format_html_report(self, ip, data):
        """Format the Cisco Talos data into HTML tables"""
        
        # Extract key information
        reputation = self._get_reputation(data)
        category = self._get_category(data)
        
        # Check for threat indicators
        threat_score = data.get('threat_score', 'N/A')
        blocked = data.get('blocked', False)
        
        # Main information table
        main_info = f"""
        <table>
            <thead>
                <tr>
                    <th colspan="2" style="background: #1e40af; color: white;">IP Address: {ip}</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Reputation</td><td><strong>{reputation}</strong></td></tr>
                <tr><td>Category</td><td>{category}</td></tr>
                <tr><td>Threat Score</td><td>{threat_score}</td></tr>
                <tr><td>Blocked Status</td><td>{'Yes' if blocked else 'No'}</td></tr>
            </tbody>
        </table>
        """
        
        # Reputation details table
        reputation_info = f"""
        <table>
            <thead>
                <tr>
                    <th colspan="2" style="background: #1e40af; color: white;">Reputation Details</th>
                </tr>
            </thead>
            <tbody>
        """
        
        # Add email reputation if available
        if 'email_reputation' in data:
            reputation_info += f"<tr><td>Email Reputation</td><td>{data['email_reputation']}</td></tr>"
        
        # Add web reputation if available
        if 'web_reputation' in data:
            reputation_info += f"<tr><td>Web Reputation</td><td>{data['web_reputation']}</td></tr>"
        
        # Add volume info if available
        if 'volume' in data:
            reputation_info += f"<tr><td>Volume</td><td>{data['volume']}</td></tr>"
        
        # Add daychange if available
        if 'daychange' in data:
            reputation_info += f"<tr><td>Day Change</td><td>{data['daychange']}</td></tr>"
        
        # Add monthchange if available
        if 'monthchange' in data:
            reputation_info += f"<tr><td>Month Change</td><td>{data['monthchange']}</td></tr>"
        
        reputation_info += """
            </tbody>
        </table>
        """
        
        # Network information table if available
        network_info = ""
        if any(key in data for key in ['asn', 'country', 'hostname', 'owner']):
            network_info = f"""
            <table>
                <thead>
                    <tr>
                        <th colspan="2" style="background: #1e40af; color: white;">Network Information</th>
                    </tr>
                </thead>
                <tbody>
            """
            
            if 'hostname' in data:
                network_info += f"<tr><td>Hostname</td><td>{data['hostname']}</td></tr>"
            if 'asn' in data:
                network_info += f"<tr><td>ASN</td><td>{data['asn']}</td></tr>"
            if 'owner' in data:
                network_info += f"<tr><td>Owner</td><td>{data['owner']}</td></tr>"
            if 'country' in data:
                network_info += f"<tr><td>Country</td><td>{data['country']}</td></tr>"
            
            network_info += """
                </tbody>
            </table>
            """
        
        return main_info + reputation_info + network_info
    
    def _format_error_html(self, ip, error_msg):
        """Format error message as HTML"""
        return f"""
        <table>
            <thead>
                <tr>
                    <th colspan="2" style="background: #ef4444; color: white;">Error for IP: {ip}</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Error</td><td>{error_msg}</td></tr>
            </tbody>
        </table>
        """