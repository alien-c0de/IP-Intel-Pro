import aiohttp
import asyncio
from colorama import Fore, Style
from utils.config_util import Configuration

class ipqualityscore:
    
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
                    
                # print(Fore.CYAN + Style.BRIGHT + f"[*] Querying IPQualityScore for {ip}..." + Fore.RESET)
                
                # Build API URL
                endpoint = f"{self.config.IPQUALITYSCORE_ENDPOINT_URL}{self.config.IPQUALITYSCORE_API_KEY}/{ip}"
                
                params = {
                    'strictness': 0,
                    'allow_public_access_points': 'true',
                    'lighter_penalties': 'true'
                }
                
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.get(endpoint, params=params, timeout=aiohttp.ClientTimeout(total=30)) as response:
                            if response.status == 200:
                                data = await response.json()
                                
                                if data.get('success'):
                                    html_content.append(self._format_html_report(ip, data))
                                    
                                    # Add to summary for CSV
                                    fraud_score = data.get('fraud_score', 'N/A')
                                    self.summary_list.append([fraud_score, data.get('ISP', 'Unknown')])
                                else:
                                    error_msg = data.get('message', 'Unknown error')
                                    html_content.append(self._format_error_html(ip, error_msg))
                                    self.summary_list.append([f"Error: {error_msg}", "N/A"])
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
            print(Fore.RED + Style.BRIGHT + f"[-] IPQualityScore Error: {error_msg}" + Fore.RESET)
            return f"<p style='color: red; margin: 20px;'>Error: {error_msg}</p>"
    
    def _format_html_report(self, ip, data):
        """Format the IPQualityScore data into HTML tables"""
        
        # Main information table
        main_info = f"""
        <table>
            <thead>
                <tr>
                    <th colspan="2" style="background: #a457ec; color: white;">IP Address: {ip}</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Fraud Score</td><td><strong>{data.get('fraud_score', 'N/A')}</strong>/100</td></tr>
                <tr><td>Country</td><td>{data.get('country_code', 'N/A')} - {data.get('region', 'N/A')}, {data.get('city', 'N/A')}</td></tr>
                <tr><td>ISP</td><td>{data.get('ISP', 'N/A')}</td></tr>
                <tr><td>Organization</td><td>{data.get('organization', 'N/A')}</td></tr>
                <tr><td>ASN</td><td>{data.get('ASN', 'N/A')}</td></tr>
                <tr><td>Host</td><td>{data.get('host', 'N/A')}</td></tr>
                <tr><td>Timezone</td><td>{data.get('timezone', 'N/A')}</td></tr>
            </tbody>
        </table>
        """
        
        # Risk assessment table
        risk_info = f"""
        <table>
            <thead>
                <tr>
                    <th colspan="2" style="background: #a457ec; color: white;">Risk Assessment</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Proxy</td><td>{'Yes' if data.get('proxy') else 'No'}</td></tr>
                <tr><td>VPN</td><td>{'Yes' if data.get('vpn') else 'No'}</td></tr>
                <tr><td>TOR</td><td>{'Yes' if data.get('tor') else 'No'}</td></tr>
                <tr><td>Active VPN</td><td>{'Yes' if data.get('active_vpn') else 'No'}</td></tr>
                <tr><td>Active TOR</td><td>{'Yes' if data.get('active_tor') else 'No'}</td></tr>
                <tr><td>Bot Status</td><td>{'Yes' if data.get('bot_status') else 'No'}</td></tr>
                <tr><td>Recent Abuse</td><td>{'Yes' if data.get('recent_abuse') else 'No'}</td></tr>
                <tr><td>Abuse Velocity</td><td>{data.get('abuse_velocity', 'N/A')}</td></tr>
            </tbody>
        </table>
        """
        
        # Connection type table
        connection_info = f"""
        <table>
            <thead>
                <tr>
                    <th colspan="2" style="background: #a457ec; color: white;">Connection Details</th>
                </tr>
            </thead>
            <tbody>
                <tr><td>Connection Type</td><td>{data.get('connection_type', 'N/A')}</td></tr>
                <tr><td>Mobile</td><td>{'Yes' if data.get('mobile') else 'No'}</td></tr>
                <tr><td>Crawlers</td><td>{'Yes' if data.get('is_crawler') else 'No'}</td></tr>
                <tr><td>Latitude</td><td>{data.get('latitude', 'N/A')}</td></tr>
                <tr><td>Longitude</td><td>{data.get('longitude', 'N/A')}</td></tr>
            </tbody>
        </table>
        """
        
        return main_info + risk_info + connection_info
    
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
