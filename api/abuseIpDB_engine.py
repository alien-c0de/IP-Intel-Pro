import asyncio
import json
import time
from datetime import datetime

import aiohttp
import numpy as np
import pandas as pd
from colorama import Fore, Style

from utils.config_util import Configuration
from utils.html_util import HTML_util


class abuseIPDB():
    abs_lst = []

    def __init__(self) -> None:
        self.abs_lst = []  # Reset list for each instance
    
    async def __link_Formating(self, ip):
        config = Configuration()
        url = config.ABUSEIPDB_ENDPOINT_URL + ip
        return url
    
    async def __formating_Input(self, decodedResponse):
        html = ""
        output = ""

        for response in decodedResponse:
            try:
                ipv4 = response['data']['ipAddress']
                # print(Fore.CYAN + Style.BRIGHT + "[+] Processing", ipv4 + Fore.RESET)
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                code = "Error Code : " + str(response["errors"][0]["status"])
                err_msg = response["errors"][0]["detail"]
                err = code + " " + err_msg
                self.abs_lst.append([err])
                msg = "[-] " + "AbuseIpDB Engine Error: Formating Input Error, " + err_msg
                print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
                continue

        print(Fore.CYAN + Style.BRIGHT + f"[+] Finished Processing AbuseIPDB" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):

        try:
            dataframe = pd.DataFrame.from_dict(decodedResponse["data"], orient='index')
            dataframe.columns = [target_url]

            # change column labels
            row_labels = {'ipAddress': 'IP Address', 'isPublic': 'Is Public', 'ipVersion': 'IP Version', 
                          'isWhitelisted': 'Is Whitelisted', 'abuseConfidenceScore': 'Abuse Confidence Score', 
                          'countryCode': 'Country Code', 'usageType': 'Usage Type', 'isp': 'ISP', 'domain': 'Domain', 
                          'hostnames': 'Hostnames', 'isTor': 'Is Tor', 'totalReports':'Total Reports', 
                          'numDistinctUsers':'Number of Distinct Users', 'lastReportedAt':'Last Reported At'}

            self.abs_lst.append([decodedResponse["data"]["abuseConfidenceScore"]])
            
            dataframe.rename(index=row_labels, inplace=True)
            html1 = dataframe.to_html(render_links=True, escape=False)
            htmlValue = html1 
        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "AbuseIpDB Engine Error: " + target_url + " Formating Output Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            htmlValue = msg
        return htmlValue

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

                responses = await asyncio.gather(*tasks)
                for response in responses:
                    # load returned json from virustotal into a python dictionary called decodedResponse
                    decodedResponse.append(await response.json())

            async for val in self.__formating_Input(decodedResponse):
                htmlTags = val
            return htmlTags

        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "AbuseIpDB Error: " + ip + " Generate Report Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return msg

    async def abuseipDB_Report(self, timestamp, target_url, isFile=False):
        config = Configuration()
        if isFile:
            iplist = []
            with open(target_url, "r") as url_file:
                for url in url_file.readlines():
                    iplist.append(url.strip())
            finalhtml = await self.generate_Report(iplist, isFile=True)
        else:
            finalhtml = await self.generate_Report(target_url, isFile=False)
        
        summary_lst = await self.__formating_list()

        HTML_Report = HTML_util(finalhtml)
        await HTML_Report.outputHTML(timestamp)
        return summary_lst

    async def __formating_list(self):
        return self.abs_lst
    
    async def get_summary_list(self):
        """Public method to get summary list"""
        return self.abs_lst