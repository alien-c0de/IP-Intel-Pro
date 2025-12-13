import asyncio
import datetime
from colorama import Fore, Style

from api.abuseIpDB_engine import abuseIPDB
from api.metadefender_engine import meta_defender
from api.virus_total_engine import virus_total
from utils.csv_util import CSV_util
from utils.html_util import HTML_util
from utils.config_util import Configuration


class engine:
    
    def __init__(self) -> None:
        pass

    async def all_Analysis(self, target_url, isFile=False):
        """
        Perform consolidated analysis using all three engines and generate a single report
        """
        try:
            config = Configuration()
            timestamp = datetime.datetime.now()
            # rep_timestamp = str(timestamp).strftime("%A %d-%b-%Y %H:%M:%S")
            
            # Initialize all engines
            vt_engine = virus_total()
            meta_engine = meta_defender()
            abuse_engine = abuseIPDB()
            
            # Run all analyses concurrently
            # print(Fore.CYAN + Style.BRIGHT + "\n[+] Querying all reputation sources..." + Fore.RESET)
            
            vt_html, meta_html, abuse_html = await asyncio.gather(
                vt_engine.generate_Report(target_url, isFile),
                meta_engine.generate_Report(target_url, isFile),
                abuse_engine.generate_Report(target_url, isFile)
            )
            
            # Get summary lists for CSV
            vt_summary = await vt_engine.get_summary_list()
            meta_summary = await meta_engine.get_summary_list()
            abuse_summary = await abuse_engine.get_summary_list()
            
            # Combine all HTML reports
            combined_html = [
                "<h2 style='margin: 40px 0 20px 50px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>VirusTotal Analysis</h2>",
                vt_html,
                "<h2 style='margin: 40px 0 20px 50px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>MetaDefender Analysis</h2>",
                meta_html,
                "<h2 style='margin: 40px 0 20px 50px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>AbuseIPDB Analysis</h2>",
                abuse_html
            ]
            
            # Generate consolidated HTML and PDF report
            print(Fore.YELLOW + Style.BRIGHT + "\n[+] Generating consolidated reports..." + Fore.RESET)
            HTML_Report = HTML_util(combined_html)
            await HTML_Report.outputHTML(timestamp)
            
            # Generate CSV summary
            # print(Fore.YELLOW + Style.BRIGHT + "[+] Generating CSV summary..." + Fore.RESET)
            csv = CSV_util()
            await csv.create_csv(timestamp, target_url, isFile, vt_summary, abuse_summary, meta_summary)
            
            # print(Fore.GREEN + Style.BRIGHT + "\n[✓] Analysis completed successfully!" + Fore.RESET)
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = f"[-] Engine Error: {error_msg}"
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)