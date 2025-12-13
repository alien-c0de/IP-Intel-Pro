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


class criminalip():
    def __init__(self) -> None:
        pass
    
    async def __link_Formating(self, ip):
        config = Configuration()
        url = config.CRIMINAL_IP_ENDPOINT_URL + ip
        return url
    
    async def __formating_Input(self, decodedResponse):
        html = ""
        output = ""

        for response in decodedResponse:
            try:
                ipv4 = response["ip"]
                # print(Fore.CYAN + Style.BRIGHT + "[+] Processing", ipv4 + Fore.RESET)
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                continue

        print(Fore.CYAN + Style.BRIGHT + "[+] Finished Processing List --> Generating " + Fore.YELLOW + f"Criminal IP Report" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):
        try:

            keys_to_remove = ["domain", "vpn", "webcam", "honeypot", "ip_category", "port", "vulnerability", "mobile", "status"]
            # iterate through the filteredResponse dictionary using the keys_to_remove array and pop to remove additional keys listed in the array
            for key in keys_to_remove:
                decodedResponse.pop(key, None)

            dataframe = pd.DataFrame.from_dict(decodedResponse, orient='index')

            issue = 'Is VPN : ' + str(decodedResponse['issues']['is_vpn']) + '<br>Is Cloud : ' + str(decodedResponse['issues']['is_cloud']) + \
                    '<br>Is TOR : ' + str(decodedResponse['issues']['is_tor']) + '<br>Is Proxy : ' + str(decodedResponse['issues']['is_proxy']) + \
                    '<br>Is Hosting : ' + str(decodedResponse['issues']['is_hosting']) + '<br>Is mobile : ' + str(decodedResponse['issues']["is_mobile"]) + \
                    '<br>Is darkweb : ' + str(decodedResponse['issues']["is_darkweb"]) + '<br>Is Snort : ' + str(decodedResponse['issues']['is_snort']) 
            score  = "Inbound : " + decodedResponse['score']["inbound"] + "<br>Outbound : " + decodedResponse['score']["outbound"] 
            whois  = ""
            if decodedResponse["whois"]["data"][0]: 
                whois = 'Name: ' + str(decodedResponse["whois"]["data"][0]["as_name"]) + \
                    '<br>No: ' + str(decodedResponse["whois"]["data"][0]["as_no"]) + \
                    '<br>City: ' + str(decodedResponse["whois"]["data"][0]["city"]) + \
                    '<br>Org Name: ' + str(decodedResponse["whois"]["data"][0]["org_name"]) + \
                    '<br>Postal Code: ' + str(decodedResponse["whois"]["data"][0]["postal_code"]) + \
                    '<br>Latitude: ' + str(decodedResponse["whois"]["data"][0]["latitude"]) + \
                    '<br>Longitude: ' + str(decodedResponse["whois"]["data"][0]["longitude"]) + \
                    '<br>Longitude: ' + str(decodedResponse["whois"]["data"][0]["longitude"]) + \
                    '<br>Org Country Code: ' + str(decodedResponse["whois"]["data"][0]["org_country_code"]) + \
                    '<br>Confirmed Time: ' + str(decodedResponse["whois"]["data"][0]["confirmed_time"]) 
            
            search_count =  str(decodedResponse["user_search_count"])
            idtext = ""
            for id in decodedResponse['ids']['data']:
                idinfo = "Classification : " + str(id["classification"]) + \
                        "<br>Url : " + str(id["url"]) + \
                        "<br>Message : " + str(id["message"]) + \
                        "<br>Source System : " + str(id["source_system"]) + \
                        "<br>Confirmed Time : " + str(id["confirmed_time"]) + "<br>"
                idtext = idtext + idinfo + "<br>"

            dataframe.columns = [target_url]
            dataframe.loc['IP Address', :] = target_url
            
            dataframe.loc['Score', :] = score 
            dataframe.loc['Issue', :] = issue
            dataframe.loc['Whois', :] = whois
            dataframe.loc['User Search Count', :] = search_count
            dataframe.loc['IDs', :] = idtext

            dataframe = dataframe.drop(['ip'], axis="index")
            dataframe = dataframe.drop(['issues'], axis="index")
            dataframe = dataframe.drop(['hostname'], axis="index")
            dataframe = dataframe.drop(['ids'], axis="index")
            dataframe = dataframe.drop(['whois'], axis="index")
            dataframe = dataframe.drop(['score'], axis="index")
            dataframe = dataframe.drop(['user_search_count'], axis="index")

            html1 = dataframe.to_html(render_links=True, escape=False)
            htmlValue = html1 

        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "Error: " + target_url + " Reading Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            htmlValue = msg
        return htmlValue

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
                    ips = list(target_url)
                else:
                    ips = list(target_url.split(","))
                for ip in ips:
                    url = await self.__link_Formating(ip)
                    tasks.append(asyncio.create_task(session.request(method="GET", url=url)))

                responses = await asyncio.gather(*tasks)
                for response in responses:
                    # load returned json from virustotal into a python dictionary called decodedResponse
                    decodedResponse.append(await response.json())

            async for val in self.__formating_Input(decodedResponse):
                htmlTags = val
            return htmlTags

        except Exception as ex:
            error_msg = ex.args[0]
            msg = "[-] " + "Error: " + ip + " Reading Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            return msg

    async def criminal_ip_Report(self, target_url, isFile=False):
        config  = Configuration()
        if isFile:
            iplist = []
            with open(target_url, "r") as url_file:
                for url in url_file.readlines():
                    iplist.append(url.strip())
            finalhtml = await self.generate_Report(iplist, isFile=True)
        else:
            finalhtml = await self.generate_Report(target_url, isFile=False)
        
        HTML_Report = HTML_util(finalhtml)
        await HTML_Report.outputHTML(config.CRIMINAL_IP_REPORT_FILE_NAME, config.CRIMINAL_IP_REPORT_TITLE, config.CRIMINAL_IP_REPORT_SUB_TITLE)