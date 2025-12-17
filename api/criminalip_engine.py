import asyncio
import aiohttp
from colorama import Fore, Style
from utils.config_util import Configuration

class criminalip():
    def __init__(self) -> None:
        self.criminal_lst = []  # Instance-level list
    
    async def __link_Formating(self, ip):
        config = Configuration()
        url = config.CRIMINAL_IP_ENDPOINT_URL + ip
        return url
    
    async def __formating_Input(self, decodedResponse):
        html = ""
        output = ""

        for response in decodedResponse:
            try:
                ipv4 = response.get("ip", "Unknown IP")
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                error_msg = str(ex)
                self.criminal_lst.append(["Error: " + error_msg])
                msg = "[-] " + "CriminalIP Engine Error: Formatting Input Error, " + error_msg
                print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
                continue

        print(Fore.CYAN + Style.BRIGHT + "[+] Finished Processing 🔍 CriminalIP" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):
        try:
            # Check for error in response
            if 'error' in decodedResponse or 'message' in decodedResponse:
                error_msg = decodedResponse.get('message', decodedResponse.get('error', 'Unknown error'))
                self.criminal_lst.append([f"Error: {error_msg}"])
                return self._format_error_html(target_url, error_msg)
            
            # Extract key information
            issues = decodedResponse.get('issues', {})
            score = decodedResponse.get('score', {})
            whois_data = decodedResponse.get('whois', {}).get('data', [])
            ids_data = decodedResponse.get('ids', {}).get('data', [])
            user_search_count = decodedResponse.get('user_search_count', 0)
            hostname = decodedResponse.get('hostname', 'N/A')
            
            # Get scores
            inbound_score = score.get('inbound', 'N/A')
            outbound_score = score.get('outbound', 'N/A')
            
            # Store for CSV
            self.criminal_lst.append([inbound_score, outbound_score])
            
            # Build main summary table with CriminalIP red header
            html_main = f"""
            <table>
                <thead>
                    <tr>
                        <th colspan="2" style="background: #1e40af; color: white;">IP Address: {target_url}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td>Hostname</td><td>{hostname}</td></tr>
                    <tr><td>Inbound Score</td><td><strong>{inbound_score}</strong></td></tr>
                    <tr><td>Outbound Score</td><td><strong>{outbound_score}</strong></td></tr>
                    <tr><td>User Search Count</td><td>{user_search_count}</td></tr>
                </tbody>
            </table>
            """
            
            # Build Issues table
            html_issues = ""
            if issues:
                html_issues = f"""
                <table style="margin-top: 15px;">
                    <thead>
                        <tr>
                            <th colspan="2" style="background: #1e40af; color: white;">Security Issues</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Is VPN</td><td>{issues.get('is_vpn', False)}</td></tr>
                        <tr><td>Is Cloud</td><td>{issues.get('is_cloud', False)}</td></tr>
                        <tr><td>Is TOR</td><td>{issues.get('is_tor', False)}</td></tr>
                        <tr><td>Is Proxy</td><td>{issues.get('is_proxy', False)}</td></tr>
                        <tr><td>Is Hosting</td><td>{issues.get('is_hosting', False)}</td></tr>
                        <tr><td>Is Mobile</td><td>{issues.get('is_mobile', False)}</td></tr>
                        <tr><td>Is Darkweb</td><td>{issues.get('is_darkweb', False)}</td></tr>
                        <tr><td>Is Snort</td><td>{issues.get('is_snort', False)}</td></tr>
                    </tbody>
                </table>
                """
            
            # Build WHOIS table
            html_whois = ""
            if whois_data and len(whois_data) > 0:
                whois_info = whois_data[0]
                html_whois = f"""
                <table style="margin-top: 15px;">
                    <thead>
                        <tr>
                            <th colspan="2" style="background: #dc2626; color: white;">WHOIS Information</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>AS Name</td><td>{whois_info.get('as_name', 'N/A')}</td></tr>
                        <tr><td>AS Number</td><td>{whois_info.get('as_no', 'N/A')}</td></tr>
                        <tr><td>Organization</td><td>{whois_info.get('org_name', 'N/A')}</td></tr>
                        <tr><td>City</td><td>{whois_info.get('city', 'N/A')}</td></tr>
                        <tr><td>Postal Code</td><td>{whois_info.get('postal_code', 'N/A')}</td></tr>
                        <tr><td>Country Code</td><td>{whois_info.get('org_country_code', 'N/A')}</td></tr>
                        <tr><td>Latitude</td><td>{whois_info.get('latitude', 'N/A')}</td></tr>
                        <tr><td>Longitude</td><td>{whois_info.get('longitude', 'N/A')}</td></tr>
                        <tr><td>Confirmed Time</td><td>{whois_info.get('confirmed_time', 'N/A')}</td></tr>
                    </tbody>
                </table>
                """
            
            # Build IDS table
            html_ids = ""
            if ids_data:
                html_ids = """
                <table style="margin-top: 15px;">
                    <thead>
                        <tr>
                            <th>Classification</th>
                            <th>Message</th>
                            <th>Source System</th>
                            <th>Confirmed Time</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                
                for id_entry in ids_data[:10]:  # Limit to 10 entries
                    classification = id_entry.get('classification', 'N/A')
                    message = id_entry.get('message', 'N/A')
                    source_system = id_entry.get('source_system', 'N/A')
                    confirmed_time = id_entry.get('confirmed_time', 'N/A')
                    
                    html_ids += f"""
                    <tr>
                        <td>{classification}</td>
                        <td>{message}</td>
                        <td>{source_system}</td>
                        <td>{confirmed_time}</td>
                    </tr>
                    """
                
                html_ids += "</tbody></table>"
            
            return html_main + html_issues + html_whois + html_ids
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "CriminalIP Engine Error: " + target_url + " Formatting Output Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return self._format_error_html(target_url, error_msg)

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
            "Accept": "application/json",
            "x-api-key": config.CRIMINAL_IP_API_KEY
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
                    url = await self.__link_Formating(ip)
                    tasks.append(asyncio.create_task(session.request(method="GET", url=url)))

                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for response in responses:
                    if isinstance(response, Exception):
                        decodedResponse.append({"error": str(response)})
                    else:
                        try:
                            decodedResponse.append(await response.json())
                        except Exception as e:
                            decodedResponse.append({"error": f"Parse error: {str(e)}"})

            async for val in self.__formating_Input(decodedResponse):
                htmlTags = val
            return htmlTags

        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "CriminalIP Error: Generate Report Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return f"<p style='color:red;'>Error generating report: {error_msg}</p>"

    async def get_summary_list(self):
        """Public method to get summary list"""
        return self.criminal_lst