import asyncio
from datetime import datetime
import aiohttp
from colorama import Fore, Style
from utils.config_util import Configuration

class meta_defender():
    def __init__(self) -> None:
        self.meta_lst = []  # Instance-level list
    
    async def __link_Formating(self, ip):
        config = Configuration()
        url = config.META_DEFENDER_ENDPOINT_URL + ip
        return url
    
    async def __formating_Input(self, decodedResponse):
        html = ""
        output = ""

        for response in decodedResponse:
            try:
                ipv4 = response["address"]
                output = await self.__formating_Output(response, ipv4)
                html = html + output
                yield html
            except Exception as ex:
                # Handle error and display in report
                try:
                    # Try to extract IP from error response
                    ipv4 = response.get("address", "Unknown IP")
                except:
                    ipv4 = "Unknown IP"
                
                try:
                    # Extract error details
                    code = "Error Code: " + str(response["error"]["code"])
                    err_msg = ' '.join(map(str, response["error"]["messages"])) 
                    err = code + " - " + err_msg
                    self.meta_lst.append([err])
                    msg = "[-] " + "MetaDefender Engine Error: Formating Input Error, " + err_msg
                    print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
                    
                    # Generate error HTML for report
                    error_html = self._format_error_html(ipv4, err)
                    html = html + error_html
                    output = error_html
                    yield html
                except:
                    error_msg = str(ex)
                    self.meta_lst.append([error_msg])
                    print(Fore.RED + Style.BRIGHT + f"[-] MetaDefender Error: {error_msg}" + Fore.RESET)
                    
                    # Generate error HTML for report
                    error_html = self._format_error_html(ipv4, error_msg)
                    html = html + error_html
                    output = error_html
                    yield html
                continue

        print(Fore.CYAN + Style.BRIGHT + "[+] Finished Processing 🔒 MetaDefender" + Fore.RESET)

    async def __formating_Output(self, decodedResponse, target_url):
        try:
            # Check if response contains error
            if "error" in decodedResponse:
                code = decodedResponse["error"].get("code", "Unknown")
                messages = decodedResponse["error"].get("messages", ["Unknown error"])
                err_msg = ' '.join(map(str, messages))
                error_text = f"Error Code {code}: {err_msg}"
                self.meta_lst.append([error_text])
                return self._format_error_html(target_url, error_text)
            
            # Extract key information
            lookup_results = decodedResponse.get("lookup_results", {})
            geo_info = decodedResponse.get("geo_info", {})
            
            community_score = lookup_results.get("detected_by", 0)
            sources = lookup_results.get("sources", [])
            total_reviewers = len(sources)
            
            # Format last analysis date
            last_analysis_date = "N/A"
            if lookup_results.get("start_time"):
                try:
                    last_analysis_date = datetime.fromisoformat(lookup_results["start_time"][:-5]).strftime('%c')
                except:
                    last_analysis_date = lookup_results["start_time"]
            
            # Format geo info
            geo_info_str = "N/A"
            if geo_info:
                country = geo_info.get("country", {}).get("name", "Unknown")
                city = geo_info.get("city", {}).get("name", "Unknown")
                location = geo_info.get("location", {})
                lat = location.get("latitude", "N/A")
                lon = location.get("longitude", "N/A")
                geo_info_str = f"Country: {country}, City: {city}, Location: {lat}, {lon}"
            else:
                geo_info_str = "There is no information available about the location of this IP address."
            
            # Store for CSV
            self.meta_lst.append([community_score, geo_info_str])
            
            # Build main summary table with MetaDefender teal header
            html_main = f"""
            <table>
                <thead>
                    <tr>
                        <th colspan="2" style="background: #14b8a6; color: white;">IP Address: {target_url}</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td>Community Score</td><td><strong>{community_score}/{total_reviewers}</strong> security vendors flagged this as malicious</td></tr>
                    <tr><td>Last Analysis Date</td><td>{last_analysis_date}</td></tr>
                    <tr><td>Geo Info</td><td>{geo_info_str}</td></tr>
                </tbody>
            </table>
            """
            
            # Build source analysis table
            html_sources = ""
            if sources:
                html_sources = """
                <table style="margin-top: 15px;">
                    <thead>
                        <tr>
                            <th>Provider</th>
                            <th>Result</th>
                            <th>Last Detected</th>
                            <th>Last Update</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                
                for source in sources:
                    provider = source.get("provider", "N/A")
                    status = source.get("status", "N/A")
                    detect_time = source.get("detect_time", "N/A")
                    update_time = source.get("update_time", "N/A")
                    
                    html_sources += f"""
                    <tr>
                        <td>{provider}</td>
                        <td>{status}</td>
                        <td>{detect_time}</td>
                        <td>{update_time}</td>
                    </tr>
                    """
                
                html_sources += "</tbody></table>"
            
            return html_main + html_sources
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "MetaDefender Engine Error: " + target_url + " Formating Output Error, " + error_msg
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
                    'apikey': config.META_DEFENDER_API_KEY
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
                
                for idx, response in enumerate(responses):
                    if isinstance(response, Exception):
                        # Handle connection/network errors
                        ip = ips[idx] if idx < len(ips) else "Unknown IP"
                        error_response = {
                            "address": ip,
                            "error": {
                                "code": "connection_error",
                                "messages": [str(response)]
                            }
                        }
                        decodedResponse.append(error_response)
                    else:
                        try:
                            json_data = await response.json()
                            # Add IP address to response if not present
                            if "address" not in json_data and idx < len(ips):
                                json_data["address"] = ips[idx]
                            decodedResponse.append(json_data)
                        except Exception as e:
                            # Handle JSON parsing errors
                            ip = ips[idx] if idx < len(ips) else "Unknown IP"
                            error_response = {
                                "address": ip,
                                "error": {
                                    "code": "parse_error",
                                    "messages": [f"Failed to parse response: {str(e)}"]
                                }
                            }
                            decodedResponse.append(error_response)

            async for val in self.__formating_Input(decodedResponse):
                htmlTags = val
            return htmlTags

        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "MetaDefender Error: Generate Report Error, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)
            
            # Return error HTML instead of just error message
            return self._format_error_html("Multiple IPs", error_msg)

    async def get_summary_list(self):
        """Public method to get summary list"""
        return self.meta_lst