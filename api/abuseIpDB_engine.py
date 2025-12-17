import asyncio
import aiohttp
from colorama import Fore, Style
from utils.config_util import Configuration

class abuseIPDB():
    abs_lst = []

    def __init__(self) -> None:
        self.abs_lst = []  # Reset list for each instance
    
    async def __formating_Input(self, decodedResponse):
        html = ""
        output = ""

        for response in decodedResponse:
            try:
                ipv4 = response['data']['ipAddress']
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                # Handle error and display in report
                try:
                    # Try to extract IP from error response
                    ipv4 = response.get('data', {}).get('ipAddress', 'Unknown IP')
                except:
                    ipv4 = "Unknown IP"
                
                try:
                    # Extract error details
                    code = "Error Code: " + str(response["errors"][0]["status"])
                    err_msg = response["errors"][0]["detail"]
                    err = code + " - " + err_msg
                    self.abs_lst.append([err])
                    msg = "[-] " + "AbuseIpDB Engine Error: Formating Input Error, " + err_msg
                    print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
                    
                    # Generate error HTML for report
                    error_html = self._format_error_html(ipv4, err)
                    html = html + error_html
                    output = error_html
                    yield html
                except:
                    error_msg = str(ex)
                    self.abs_lst.append([error_msg])
                    print(Fore.RED + Style.BRIGHT + f"[-] AbuseIPDB Error: {error_msg}" + Fore.RESET)
                    
                    # Generate error HTML for report
                    error_html = self._format_error_html(ipv4, error_msg)
                    html = html + error_html
                    output = error_html
                    yield html
                continue

        print(Fore.CYAN + Style.BRIGHT + f"[+] Finished Processing ⚠️ AbuseIPDB" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):
        try:
            # Check if response contains error
            if "errors" in decodedResponse:
                code = decodedResponse["errors"][0].get("status", "Unknown")
                err_msg = decodedResponse["errors"][0].get("detail", "Unknown error")
                error_text = f"Error Code {code}: {err_msg}"
                self.abs_lst.append([error_text])
                return self._format_error_html(target_url, error_text)
            
            data = decodedResponse.get("data", {})
            
            if not data:
                return self._format_error_html(target_url, "No data available")
            
            # Build HTML table manually for better styling
            html = f"""
            <table>
                <thead>
                    <tr>
                        <th colspan="2" style="background: #f59e0b; color: white;">IP Address: {target_url}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td>Is Public</td><td>{data.get('isPublic', 'N/A')}</td></tr>
                    <tr><td>IP Version</td><td>{data.get('ipVersion', 'N/A')}</td></tr>
                    <tr><td>Is Whitelisted</td><td>{data.get('isWhitelisted', 'N/A')}</td></tr>
                    <tr><td>Abuse Confidence Score</td><td><strong>{data.get('abuseConfidenceScore', 'N/A')}</strong></td></tr>
                    <tr><td>Country Code</td><td>{data.get('countryCode', 'N/A')}</td></tr>
                    <tr><td>Usage Type</td><td>{data.get('usageType', 'N/A')}</td></tr>
                    <tr><td>ISP</td><td>{data.get('isp', 'N/A')}</td></tr>
                    <tr><td>Domain</td><td>{data.get('domain', 'N/A')}</td></tr>
                    <tr><td>Hostnames</td><td>{', '.join(data.get('hostnames', [])) if data.get('hostnames') else 'N/A'}</td></tr>
                    <tr><td>Is Tor</td><td>{data.get('isTor', 'N/A')}</td></tr>
                    <tr><td>Total Reports</td><td>{data.get('totalReports', 'N/A')}</td></tr>
                    <tr><td>Number of Distinct Users</td><td>{data.get('numDistinctUsers', 'N/A')}</td></tr>
                    <tr><td>Last Reported At</td><td>{data.get('lastReportedAt', 'N/A')}</td></tr>
                </tbody>
            </table>
            """
            
            # Store score for CSV
            self.abs_lst.append([data.get("abuseConfidenceScore", "N/A")])
            
            return html
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "AbuseIpDB Engine Error: " + target_url + " Formating Output Error, " + error_msg
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
                <tr><td>Error Details</td><td>{error_msg}</td></tr>
            </tbody>
        </table>
        """

    async def generate_Report(self, target_url, isFile=False):
        config = Configuration()
        htmlTags = ""
        tasks = []
        decodedResponse = []

        headers = {
            'Accept': 'application/json',
            'Key': config.ABUSEIPDB_API_KEY}
        
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
                    url = config.ABUSEIPDB_ENDPOINT_URL
                    querystring = {'ipAddress': ip,
                                    'maxAgeInDays': '90'
                                  }
                    tasks.append(asyncio.create_task(session.request(method="GET", url=url, params=querystring)))

                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for idx, response in enumerate(responses):
                    if isinstance(response, Exception):
                        # Handle connection/network errors
                        ip = ips[idx] if idx < len(ips) else "Unknown IP"
                        error_response = {
                            "data": {
                                "ipAddress": ip
                            },
                            "errors": [{
                                "status": "connection_error",
                                "detail": str(response)
                            }]
                        }
                        decodedResponse.append(error_response)
                    else:
                        try:
                            json_data = await response.json()
                            # Add IP to error responses if not present
                            if "errors" in json_data and "data" not in json_data and idx < len(ips):
                                json_data["data"] = {
                                    "ipAddress": ips[idx]
                                }
                            decodedResponse.append(json_data)
                        except Exception as e:
                            # Handle JSON parsing errors
                            ip = ips[idx] if idx < len(ips) else "Unknown IP"
                            error_response = {
                                "data": {
                                    "ipAddress": ip
                                },
                                "errors": [{
                                    "status": "parse_error",
                                    "detail": f"Failed to parse response: {str(e)}"
                                }]
                            }
                            decodedResponse.append(error_response)

            async for val in self.__formating_Input(decodedResponse):
                htmlTags = val
            return htmlTags

        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "AbuseIpDB Error: Generate Report Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            
            # Return error HTML instead of just error message
            return self._format_error_html("Multiple IPs", error_msg)

    async def get_summary_list(self):
        """Public method to get summary list"""
        return self.abs_lst