import asyncio
import aiohttp
import pandas as pd
from colorama import Fore, Style
from utils.config_util import Configuration
from utils.html_util import HTML_util


class greynoise():
    def __init__(self):
        self.gn_lst = []  # Instance-level list

    async def __formating_Input(self, decodedResponse):
        html = ""
        output = ""
        for response in decodedResponse:
            try:
                ipv4 = response.get('ip', 'Unknown IP')
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                error_msg = str(ex)
                self.gn_lst.append(["Error: " + error_msg])
                msg = "[-] " + "GreyNoise Engine Error: Formatting Input Error, " + error_msg
                print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
                continue

        print(Fore.CYAN + Style.BRIGHT + "[+] Finished Processing GreyNoise" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):
        try:
            # Handle error responses
            if 'error' in decodedResponse:
                error_msg = decodedResponse.get('error', 'Unknown error')
                self.gn_lst.append([error_msg])
                return self._format_error_html(target_url, error_msg)
            
            # Check if IP is in GreyNoise dataset
            seen = decodedResponse.get('seen', False)
            
            if not seen:
                self.gn_lst.append(["Not seen", "Unknown"])
                
                # Build table for unseen IP with GreyNoise green header
                html = f"""
                <table>
                    <thead>
                        <tr>
                            <th colspan="2" style="background: #10b981; color: white;">IP Address: {target_url}</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Status</td><td>Not observed by GreyNoise</td></tr>
                        <tr><td>Classification</td><td>Unknown</td></tr>
                        <tr><td>Noise Level</td><td>Not in dataset</td></tr>
                        <tr><td>Riot (Trust List)</td><td>{'Yes' if decodedResponse.get('riot', False) else 'No'}</td></tr>
                        <tr><td>Risk Level</td><td>Unknown - Not in GreyNoise dataset</td></tr>
                    </tbody>
                </table>
                """
            else:
                # Extract key information
                classification = decodedResponse.get('classification', 'Unknown')
                name = decodedResponse.get('name', 'Unknown')
                link = decodedResponse.get('link', '')
                last_seen = decodedResponse.get('last_seen', 'Unknown')
                message = decodedResponse.get('message', '')
                riot = decodedResponse.get('riot', False)
                
                # Store for CSV
                self.gn_lst.append([classification, name])
                
                # Build main summary table with GreyNoise green header
                html = f"""
                <table>
                    <thead>
                        <tr>
                            <th colspan="2" style="background: #10b981; color: white;">IP Address: {target_url}</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Classification</td><td><strong>{classification}</strong></td></tr>
                        <tr><td>Service Name</td><td>{name}</td></tr>
                        <tr><td>Last Seen</td><td>{last_seen}</td></tr>
                        <tr><td>Riot (Trust List)</td><td>{'Yes' if riot else 'No'}</td></tr>
                        <tr><td>Risk Level</td><td>{self.__get_classification_info(classification)}</td></tr>
                        <tr><td>Message</td><td>{message if message else 'No additional information'}</td></tr>
                """
                
                if link:
                    html += f"""
                        <tr><td>GreyNoise Link</td><td><a href="{link}" target="_blank">View Details</a></td></tr>
                    """
                
                html += """
                    </tbody>
                </table>
                """
                
                # Add context information
                html += f"""
                <table style="margin-top: 15px;">
                    <thead>
                        <tr>
                            <th colspan="2" style="background: #059669; color: white;">GreyNoise Context</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td colspan="2">
                                <strong>What is GreyNoise?</strong> GreyNoise identifies IPs that are scanning the internet 
                                and classifies them as benign or malicious. This helps security teams filter out internet background noise.
                            </td>
                        </tr>
                        <tr>
                            <td colspan="2">
                                <strong>Classification Guide:</strong><br>
                                • <strong>Malicious:</strong> Known bad actors, attackers<br>
                                • <strong>Benign:</strong> Legitimate services (crawlers, scanners)<br>
                                • <strong>Unknown:</strong> Observed but not yet classified
                            </td>
                        </tr>
                    </tbody>
                </table>
                """
            
            return html
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "GreyNoise Engine Error: " + target_url + " Formatting Output Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return self._format_error_html(target_url, error_msg)

    def __get_classification_info(self, classification):
        """Convert classification to risk level with description"""
        classification = classification.lower()
        if classification == 'malicious':
            return "High Risk - Known malicious activity"
        elif classification == 'benign':
            return "Low Risk - Legitimate internet scanner"
        elif classification == 'unknown':
            return "Medium Risk - Observed but unclassified"
        else:
            return "Unknown - Not in GreyNoise dataset"

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
            "key": config.GREYNOISE_API_KEY
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
                    url = f"{config.GREYNOISE_ENDPOINT_URL}{ip}"
                    tasks.append(asyncio.create_task(session.request(method="GET", url=url)))
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for response in responses:
                    if isinstance(response, Exception):
                        decodedResponse.append({"error": str(response)})
                    else:
                        try:
                            data = await response.json()
                            decodedResponse.append(data)
                        except Exception as e:
                            decodedResponse.append({"error": f"Parse error: {str(e)}"})
            
            async for val in self.__formating_Input(decodedResponse):
                htmlTags = val
            return htmlTags
        
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "GreyNoise Error: Generate Report Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return f"<p style='color:red;'>Error generating report: {error_msg}</p>"

    async def get_summary_list(self):
        """Public method to get summary list"""
        return self.gn_lst