import asyncio
import aiohttp
import base64
import hashlib
import re
import time

import pandas as pd
from colorama import Fore, Style

from utils.config_util import Configuration
from utils.html_util import HTML_util


class virus_total():
    def __init__(self, islist=False):
        self.__islist = islist
        self.vt_lst = []  # Instance-level list

    async def __encrypt_string(self, hash_string):
        sha_signature = hashlib.sha256(hash_string.encode()).hexdigest()
        return sha_signature

    async def __link_Formating(self, target_url):
        config = Configuration()
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        url = config.VIRUS_TOTAL_ENDPOINT_URL + url_id
        return url

    async def __find_ip_address(self, string):
        pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        match = re.search(pattern, string)
        if match:
            return match.group()
        else:
            return None

    async def formating_Input(self, decodedResponse):
        html = ""
        output = ""
        for response in decodedResponse:
            try:
                ipv4 = await self.__find_ip_address(response["data"]["attributes"]["url"])
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                try:
                    code = "Error Code : " + str(response["error"]["code"])
                    err_msg = response["error"]["message"]
                    err = code + " " + err_msg
                except:
                    err = str(ex)
                
                self.vt_lst.append([err])
                msg = "[-] " + "VirusTotal Engine Error: Formatting Input Error, " + str(err)
                print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
                continue

        print(Fore.CYAN + Style.BRIGHT + "[+] Finished Processing VirusTotal" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):
        try:
            config = Configuration()
            
            attributes = decodedResponse.get("data", {}).get("attributes", {})
            
            if not attributes:
                return self._format_error_html(target_url, "No data available")
            
            epoch_time = attributes.get("last_analysis_date", int(time.time()))
            time_formatted = time.strftime('%c', time.localtime(epoch_time))
            
            UrlId_unEncrypted = ("http://" + target_url + "/")
            sha_signature = await self.__encrypt_string(UrlId_unEncrypted)
            vt_urlReportLink = (config.VIRUS_TOTAL_REPORT_LINK + sha_signature)
            
            # Get last_analysis_stats
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            if isinstance(last_analysis_stats, dict):
                malicious = int(last_analysis_stats.get("malicious", 0))
                harmless = int(last_analysis_stats.get("harmless", 0))
                suspicious = int(last_analysis_stats.get("suspicious", 0))
                undetected = int(last_analysis_stats.get("undetected", 0))
                timeout = int(last_analysis_stats.get("timeout", 0))
            else:
                malicious = harmless = suspicious = undetected = timeout = 0
            
            self.vt_lst.append([malicious])
            
            total_vt_reviewers = harmless + malicious + suspicious + undetected + timeout
            
            # Build main summary table with VirusTotal purple header
            html_main = f"""
            <table>
                <thead>
                    <tr>
                        <th colspan="2" style="background: #8b5cf6; color: white;">IP Address: {target_url}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td>Community Score</td><td><strong>{malicious}/{total_vt_reviewers}</strong> security vendors flagged this as malicious</td></tr>
                    <tr><td>Last Analysis Date</td><td>{time_formatted}</td></tr>
                    <tr><td>Reputation</td><td>{attributes.get('reputation', 'N/A')}</td></tr>
                    <tr><td>Times Submitted</td><td>{attributes.get('times_submitted', 'N/A')}</td></tr>
                    <tr><td>Last Final URL</td><td>{attributes.get('last_final_url', 'N/A')}</td></tr>
                    <tr><td>Last Analysis Stats</td><td>Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}, Undetected: {undetected}</td></tr>
                    <tr><td>VirusTotal Report</td><td><a href="{vt_urlReportLink}" target="_blank">View Full Report</a></td></tr>
                </tbody>
            </table>
            """
            
            # Get analysis results
            lastAnalysisResponse = attributes.get("last_analysis_results", {})
            
            html_analysis = ""
            if lastAnalysisResponse and isinstance(lastAnalysisResponse, dict):
                try:
                    # Build analysis results table
                    results = []
                    for engine, result in lastAnalysisResponse.items():
                        if isinstance(result, dict):
                            results.append({
                                'Engine Name': engine,
                                'Category': result.get('category', 'N/A'),
                                'Result': result.get('result', 'N/A'),
                                'Method': result.get('method', 'N/A')
                            })
                    
                    if results:
                        # Sort by category (malicious first)
                        results_sorted = sorted(results, key=lambda x: (
                            0 if x['Category'] == 'malicious' else
                            1 if x['Category'] == 'suspicious' else
                            2 if x['Category'] == 'undetected' else 3
                        ))
                        
                        html_analysis = """
                        <table style="margin-top: 15px;">
                            <thead>
                                <tr>
                                    <th>Engine Name</th>
                                    <th>Category</th>
                                    <th>Result</th>
                                    <th>Method</th>
                                </tr>
                            </thead>
                            <tbody>
                        """
                        
                        for result in results_sorted:
                            html_analysis += f"""
                            <tr>
                                <td>{result['Engine Name']}</td>
                                <td>{result['Category']}</td>
                                <td>{result['Result']}</td>
                                <td>{result['Method']}</td>
                            </tr>
                            """
                        
                        html_analysis += "</tbody></table>"
                        
                except Exception as e:
                    html_analysis = f"<p style='margin: 10px 0;'>Analysis results available but could not be formatted: {str(e)}</p>"
            
            return html_main + html_analysis
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "VirusTotal Engine Error: " + target_url + " Formatting Output Error, " + error_msg
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
            "x-apikey": config.VIRUS_TOTAL_API_KEY
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
                        decodedResponse.append({"error": {"code": "connection", "message": str(response)}})
                    else:
                        try:
                            decodedResponse.append(await response.json())
                        except Exception as e:
                            decodedResponse.append({"error": {"code": "parse", "message": str(e)}})

            async for val in self.formating_Input(decodedResponse):
                htmlTags = val
            return htmlTags

        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "VirusTotal Error: Generate Report Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return f"<p style='color:red;'>Error generating report: {error_msg}</p>"

    async def get_summary_list(self):
        """Public method to get summary list"""
        return self.vt_lst