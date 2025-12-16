import asyncio
import aiohttp
import pandas as pd
from colorama import Fore, Style
from utils.config_util import Configuration
from utils.html_util import HTML_util


class alienvault_otx():
    def __init__(self):
        self.otx_lst = []  # Instance-level list

    async def __formating_Input(self, decodedResponse):
        html = ""
        output = ""
        for response in decodedResponse:
            try:
                ipv4 = response.get('indicator', 'Unknown IP')
                # print(Fore.CYAN + Style.BRIGHT + "[+] Processing", ipv4 + Fore.RESET)
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                error_msg = str(ex)
                self.otx_lst.append(["Error: " + error_msg])
                msg = "[-] " + "AlienVault OTX Engine Error: Formatting Input Error, " + error_msg
                print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
                continue

        print(Fore.CYAN + Style.BRIGHT + "[+] Finished Processing AlienVault OTX" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):
        try:
            # Extract key information
            general_info = decodedResponse.get('general', {})
            reputation = decodedResponse.get('reputation', {})
            geo_data = decodedResponse.get('geo', {})
            malware_data = decodedResponse.get('malware', {})
            url_list = decodedResponse.get('url_list', {})
            passive_dns = decodedResponse.get('passive_dns', {})
            
            # Create main summary dataframe
            summary_data = {}
            
            # Reputation and threat data
            reputation_score = reputation.get('threat_score', 0) if reputation else 0
            reputation_counts = reputation.get('counts', {}) if reputation else {}
            
            summary_data['Reputation Score'] = f"{reputation_score}/7"
            summary_data['Reputation Level'] = self.__get_reputation_level(reputation_score)
            
            # Pulse information
            pulse_count = general_info.get('pulse_info', {}).get('count', 0)
            summary_data['Threat Pulses'] = pulse_count
            
            # Store for CSV
            self.otx_lst.append([reputation_score])
            
            # Geographic information
            if geo_data:
                country = geo_data.get('country_name', 'Unknown')
                city = geo_data.get('city', 'Unknown')
                summary_data['Country'] = country
                summary_data['City'] = city
                summary_data['Continent'] = geo_data.get('continent_code', 'Unknown')
                summary_data['Latitude'] = geo_data.get('latitude', 'N/A')
                summary_data['Longitude'] = geo_data.get('longitude', 'N/A')
            
            # ASN Information
            summary_data['ASN'] = general_info.get('asn', 'Unknown')
            
            # Malware samples
            if malware_data:
                malware_count = malware_data.get('count', 0)
                summary_data['Malware Samples'] = malware_count
            
            # URLs associated
            if url_list:
                url_count = url_list.get('url_count', 0)
                summary_data['Associated URLs'] = url_count
            
            # Passive DNS
            if passive_dns:
                dns_count = passive_dns.get('count', 0)
                summary_data['Passive DNS Records'] = dns_count
            
            # Create summary dataframe
            dataframe = pd.DataFrame.from_dict(summary_data, orient='index')
            dataframe.columns = [target_url]
            dataframe.sort_index(inplace=True)
            
            html1 = dataframe.to_html(render_links=True, escape=False)
            
            # Create detailed pulse information table
            html2 = ""
            pulses = general_info.get('pulse_info', {}).get('pulses', [])
            if pulses:
                pulse_data = []
                for pulse in pulses[:10]:  # Limit to top 10 pulses
                    pulse_data.append({
                        'Pulse Name': pulse.get('name', 'Unknown'),
                        'Tags': ', '.join(pulse.get('tags', [])),
                        'Created': pulse.get('created', 'Unknown'),
                        'TLP': pulse.get('TLP', 'Unknown'),
                        'Threat Score': pulse.get('threat_score', 0)
                    })
                
                if pulse_data:
                    pulse_df = pd.DataFrame(pulse_data)
                    # html2 = "<h4 style='margin: 20px 0 10px 0;'>Recent Threat Pulses (Top 10)</h4>" + pulse_df.to_html(render_links=True, escape=False, index=False)
                    html2 = pulse_df.to_html(render_links=True, escape=False, index=False)
            
            htmlValue = html1 + html2
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "AlienVault OTX Engine Error: " + target_url + " Formatting Output Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            htmlValue = f"<p style='color:red;'>Error processing {target_url}: {error_msg}</p>"
        return htmlValue

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
                    # Get general information
                    url = f"{config.ALIENVAULT_OTX_ENDPOINT_URL}{ip}/general"
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
