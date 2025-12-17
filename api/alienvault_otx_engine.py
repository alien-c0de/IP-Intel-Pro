import asyncio
import aiohttp
from colorama import Fore, Style
from utils.config_util import Configuration

class alienvault_otx():
    def __init__(self):
        self.otx_lst = []  # Instance-level list

    async def __formating_Input(self, decodedResponse):
        html = ""
        output = ""
        for response in decodedResponse:
            try:
                ipv4 = response.get('indicator', 'Unknown IP')
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                error_msg = str(ex)
                self.otx_lst.append(["Error: " + error_msg])
                msg = "[-] " + "AlienVault OTX Engine Error: Formatting Input Error, " + error_msg
                print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
                continue

        print(Fore.CYAN + Style.BRIGHT + "[+] Finished Processing 🔬 AlienVault OTX" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):
        try:
            # Check for error in response
            if 'error' in decodedResponse:
                error_msg = decodedResponse.get('error', {}).get('message', 'Unknown error')
                self.otx_lst.append([f"Error: {error_msg}"])
                return self._format_error_html(target_url, error_msg)
            
            # Extract key information
            general_info = decodedResponse.get('general', {})
            reputation = decodedResponse.get('reputation', {})
            geo_data = decodedResponse.get('geo', {})
            malware_data = decodedResponse.get('malware', {})
            url_list = decodedResponse.get('url_list', {})
            passive_dns = decodedResponse.get('passive_dns', {})
            
            # Reputation and threat data
            reputation_score = reputation.get('threat_score', 0) if reputation else 0
            pulse_count = general_info.get('pulse_info', {}).get('count', 0)
            
            # Store for CSV
            self.otx_lst.append([reputation_score])
            
            # Geographic information
            country = "Unknown"
            city = "Unknown"
            continent = "Unknown"
            latitude = "N/A"
            longitude = "N/A"
            
            if geo_data:
                country = geo_data.get('country_name', 'Unknown')
                city = geo_data.get('city', 'Unknown')
                continent = geo_data.get('continent_code', 'Unknown')
                latitude = geo_data.get('latitude', 'N/A')
                longitude = geo_data.get('longitude', 'N/A')
            
            # ASN information
            asn = general_info.get('asn', 'Unknown')
            
            # Malware, URLs, DNS counts
            malware_count = malware_data.get('count', 0) if malware_data else 0
            url_count = url_list.get('url_count', 0) if url_list else 0
            dns_count = passive_dns.get('count', 0) if passive_dns else 0
            
            # Build main summary table with AlienVault blue header
            html_main = f"""
            <table>
                <thead>
                    <tr>
                        <th colspan="2" style="background: #3b82f6; color: white;">IP Address: {target_url}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td>Reputation Score</td><td><strong>{reputation_score}/7</strong></td></tr>
                    <tr><td>Reputation Level</td><td>{self.__get_reputation_level(reputation_score)}</td></tr>
                    <tr><td>Threat Pulses</td><td>{pulse_count}</td></tr>
                    <tr><td>Country</td><td>{country}</td></tr>
                    <tr><td>City</td><td>{city}</td></tr>
                    <tr><td>Continent</td><td>{continent}</td></tr>
                    <tr><td>Latitude</td><td>{latitude}</td></tr>
                    <tr><td>Longitude</td><td>{longitude}</td></tr>
                    <tr><td>ASN</td><td>{asn}</td></tr>
                    <tr><td>Malware Samples</td><td>{malware_count}</td></tr>
                    <tr><td>Associated URLs</td><td>{url_count}</td></tr>
                    <tr><td>Passive DNS Records</td><td>{dns_count}</td></tr>
                </tbody>
            </table>
            """
            
            # Create detailed pulse information table
            html_pulses = ""
            pulses = general_info.get('pulse_info', {}).get('pulses', [])
            if pulses:
                html_pulses = """
                <table style="margin-top: 15px;">
                    <thead>
                        <tr>
                            <th>Pulse Name</th>
                            <th>Tags</th>
                            <th>Created</th>
                            <th>TLP</th>
                            <th>Threat Score</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                
                for pulse in pulses[:10]:  # Limit to top 10 pulses
                    pulse_name = pulse.get('name', 'Unknown')
                    tags = ', '.join(pulse.get('tags', []))
                    created = pulse.get('created', 'Unknown')
                    tlp = pulse.get('TLP', 'Unknown')
                    threat_score = pulse.get('threat_score', 0)
                    
                    html_pulses += f"""
                    <tr>
                        <td>{pulse_name}</td>
                        <td>{tags if tags else 'N/A'}</td>
                        <td>{created}</td>
                        <td>{tlp}</td>
                        <td>{threat_score}</td>
                    </tr>
                    """
                
                html_pulses += "</tbody></table>"
            
            return html_main + html_pulses
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "AlienVault OTX Engine Error: " + target_url + " Formatting Output Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return self._format_error_html(target_url, error_msg)

    def __get_reputation_level(self, score):
        """Convert numeric reputation score to text level"""
        if score >= 5:
            return "High Risk"
        elif score >= 3:
            return "Medium Risk"
        elif score >= 1:
            return "Low Risk"
        else:
            return "Clean"

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

    async def generate_Report(self, target_url, isFile=False):
        config = Configuration()
        htmlTags = ""
        tasks = []
        decodedResponse = []
        
        headers = {
            "X-OTX-API-KEY": config.ALIENVAULT_OTX_API_KEY
        }
        
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                if isFile:
                    ips = []
                    with open(target_url, "r") as url_file:
                        for url in url_file.readlines():
                            ips.append(url.strip())
                else:
                    ips = list(target_url.split(","))
                
                for ip in ips:
                    tasks.append(asyncio.create_task(self.__fetch_otx_data(session, ip)))
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for response in responses:
                    if isinstance(response, Exception):
                        decodedResponse.append({"error": {"message": str(response)}})
                    else:
                        decodedResponse.append(response)
            
            async for val in self.__formating_Input(decodedResponse):
                htmlTags = val
            return htmlTags
        
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "AlienVault OTX Error: Generate Report Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return f"<p style='color:red;'>Error generating report: {error_msg}</p>"

    async def __fetch_otx_data(self, session, ip):
        """Fetch comprehensive OTX data for an IP"""
        config = Configuration()
        base_url = config.ALIENVAULT_OTX_ENDPOINT_URL
        
        # Fetch multiple endpoints
        endpoints = ['general', 'reputation', 'geo', 'malware', 'url_list', 'passive_dns']
        
        combined_data = {'indicator': ip}
        
        for endpoint in endpoints:
            try:
                url = f"{base_url}{ip}/{endpoint}"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        combined_data[endpoint] = data
                    else:
                        combined_data[endpoint] = {}
            except Exception as e:
                combined_data[endpoint] = {}
                print(Fore.YELLOW + Style.BRIGHT + f"[!] Warning: Could not fetch {endpoint} for {ip}: {str(e)}" + Fore.RESET)
        
        return combined_data

    async def get_summary_list(self):
        """Public method to get summary list"""
        return self.otx_lst