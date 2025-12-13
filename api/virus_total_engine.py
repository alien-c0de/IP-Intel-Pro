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
            
            # Safely access nested data with defaults
            attributes = decodedResponse.get("data", {}).get("attributes", {})
            
            if not attributes:
                return f"<p style='color:orange;'>No data available for {target_url}</p>"
            
            epoch_time = attributes.get("last_analysis_date", int(time.time()))
            time_formatted = time.strftime('%c', time.localtime(epoch_time))
            
            UrlId_unEncrypted = ("http://" + target_url + "/")
            sha_signature = await self.__encrypt_string(UrlId_unEncrypted)
            vt_urlReportLink = (config.VIRUS_TOTAL_REPORT_LINK + sha_signature)
            
            # Create a clean copy for the dataframe - only include serializable fields
            filteredResponse = {}
            
            # Safely extract only the fields we want
            safe_fields = ['reputation', 'times_submitted', 'last_final_url', 'crowdsourced_context']
            for field in safe_fields:
                if field in attributes:
                    value = attributes[field]
                    # Convert non-serializable types to strings
                    if isinstance(value, (dict, list)):
                        filteredResponse[field] = str(value)
                    elif isinstance(value, (str, int, float, bool)) or value is None:
                        filteredResponse[field] = value
                    else:
                        filteredResponse[field] = str(value)
            
            # Get last_analysis_stats safely
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            if isinstance(last_analysis_stats, dict):
                malicious = int(last_analysis_stats.get("malicious", 0))
                harmless = int(last_analysis_stats.get("harmless", 0))
                suspicious = int(last_analysis_stats.get("suspicious", 0))
                undetected = int(last_analysis_stats.get("undetected", 0))
                timeout = int(last_analysis_stats.get("timeout", 0))
                
                # Add stats as string for display
                filteredResponse['last_analysis_stats'] = str(last_analysis_stats)
            else:
                malicious = 0
                harmless = 0
                suspicious = 0
                undetected = 0
                timeout = 0
            
            self.vt_lst.append([malicious])
            
            # Create dataframe only if we have data
            if filteredResponse:
                dataframe = pd.DataFrame.from_dict(filteredResponse, orient='index')
                dataframe.columns = [target_url]
            else:
                # Create empty dataframe with IP column
                dataframe = pd.DataFrame(columns=[target_url])
            
            community_score = malicious
            total_vt_reviewers = harmless + malicious + suspicious + undetected + timeout

            community_score_info = f"{community_score}/{total_vt_reviewers} security vendors flagged this as malicious"
            
            dataframe.loc['Community Score', :] = community_score_info
            dataframe.loc['Last Analysis Date', :] = time_formatted
            dataframe.loc['VirusTotal Report Link', :] = vt_urlReportLink
            
            row_labels = {
                'last_analysis_stats': 'Last Analysis Stats', 
                'reputation': 'Reputation', 
                'times_submitted': 'Times Submitted', 
                'last_final_url': 'Last Final URL',
                'crowdsourced_context': 'Crowdsourced Context'
            }
            dataframe.rename(index=row_labels, inplace=True)
            dataframe.sort_index(inplace=True)
            
            # Get analysis results
            lastAnalysisResponse = attributes.get("last_analysis_results", {})
            
            col_labels = {'category': 'Category', 'result': 'Result', 'method': 'Method', 'engine_name': 'Engine Name'}
            
            if lastAnalysisResponse and isinstance(lastAnalysisResponse, dict):
                try:
                    vt_analysis_result = pd.DataFrame.from_dict(lastAnalysisResponse, orient="index")
                    vt_analysis_result = vt_analysis_result.sort_values(by=['category'], ascending=False)
                    vt_analysis_result.rename(columns=col_labels, inplace=True)
                    html2 = vt_analysis_result.to_html(render_links=True, escape=False)
                except Exception as e:
                    html2 = f"<p>Analysis results available but could not be formatted: {str(e)}</p>"
            else:
                html2 = "<p>No detailed analysis results available.</p>"

            html1 = dataframe.to_html(render_links=True, escape=False)
            htmlValue = html1 + html2
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "VirusTotal Engine Error: " + target_url + " Formatting Output Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            htmlValue = f"<p style='color:red;'>Error processing {target_url}: {error_msg}</p>"
        return htmlValue

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
                            # ips = list(target_url)
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

    async def virus_total_Report(self, timestamp, target_url, isFile=False):
        config = Configuration()
        if isFile:
            iplist = []
            with open(target_url, "r") as url_file:
                for url in url_file.readlines():
                    iplist.append(url.strip())
            finalhtml = await self.generate_Report(iplist, isFile=True)
        else:
            finalhtml = await self.generate_Report(target_url, isFile=False)

        summary_lst = self.vt_lst
        HTML_Report = HTML_util(finalhtml)
        await HTML_Report.outputHTML(config.VIRUS_TOTAL_REPORT_FILE_NAME, timestamp)
        return summary_lst
    
    async def get_summary_list(self):
        """Public method to get summary list"""
        return self.vt_lst