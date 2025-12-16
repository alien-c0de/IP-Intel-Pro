import asyncio
import datetime
from colorama import Fore, Style

from api.abuseIpDB_engine import abuseIPDB
from api.metadefender_engine import meta_defender
from api.virus_total_engine import virus_total
from api.alienvault_otx_engine import alienvault_otx
from api.greynoise_engine import greynoise
from api.ipqualityscore_engine import ipqualityscore
from api.cisco_talos_engine import cisco_talos
from utils.csv_util import CSV_util
from utils.html_util import HTML_util
from utils.config_util import Configuration


class engine:
    
    def __init__(self) -> None:
        pass

    async def all_Analysis(self, target_url, isFile=False):
        """
        Perform consolidated analysis using all seven engines and generate a single report
        """
        try:
            config = Configuration()
            timestamp = datetime.datetime.now()
            
            # Initialize all engines
            vt_engine = virus_total()
            meta_engine = meta_defender()
            abuse_engine = abuseIPDB()
            otx_engine = alienvault_otx()
            gn_engine = greynoise()
            ipqs_engine = ipqualityscore()
            # talos_engine = cisco_talos()
            
            # Run all analyses concurrently
            vt_html, meta_html, abuse_html, otx_html, gn_html, ipqs_html = await asyncio.gather(
                vt_engine.generate_Report(target_url, isFile),
                meta_engine.generate_Report(target_url, isFile),
                abuse_engine.generate_Report(target_url, isFile),
                otx_engine.generate_Report(target_url, isFile),
                gn_engine.generate_Report(target_url, isFile),
                ipqs_engine.generate_Report(target_url, isFile),
                # talos_engine.generate_Report(target_url, isFile)
            )
            
            # Get summary lists for CSV
            vt_summary = await vt_engine.get_summary_list()
            meta_summary = await meta_engine.get_summary_list()
            abuse_summary = await abuse_engine.get_summary_list()
            otx_summary = await otx_engine.get_summary_list()
            gn_summary = await gn_engine.get_summary_list()
            ipqs_summary = await ipqs_engine.get_summary_list()
            # talos_summary = await talos_engine.get_summary_list()
            
            # Combine all HTML reports
            combined_html = [
                "<h2 style='margin: 40px 0 20px 50px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>VirusTotal Analysis</h2>",
                vt_html,
                "<h2 style='margin: 40px 0 20px 50px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>MetaDefender Analysis</h2>",
                meta_html,
                "<h2 style='margin: 40px 0 20px 50px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>AbuseIPDB Analysis</h2>",
                abuse_html,
                "<h2 style='margin: 40px 0 20px 50px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>AlienVault OTX Analysis</h2>",
                otx_html,
                "<h2 style='margin: 40px 0 20px 50px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>GreyNoise Analysis</h2>",
                gn_html,
                "<h2 style='margin: 40px 0 20px 50px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>IPQualityScore Analysis</h2>",
                ipqs_html
                # "<h2 style='margin: 40px 0 20px 50px; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;'>Cisco Talos Intelligence Analysis</h2>",
                # talos_html
            ]
            
            # Generate consolidated HTML and PDF report
            print(Fore.YELLOW + Style.BRIGHT + "\n[+] Generating consolidated reports..." + Fore.RESET)
            HTML_Report = HTML_util(combined_html)
            await HTML_Report.outputHTML(timestamp)
            
            # Generate CSV summary
            csv = CSV_util()
            # await csv.create_csv(timestamp, target_url, isFile, vt_summary, abuse_summary, meta_summary, 
            #                     otx_summary, gn_summary, ipqs_summary, talos_summary)
            await csv.create_csv(timestamp, target_url, isFile, vt_summary, abuse_summary, meta_summary, 
                                otx_summary, gn_summary, ipqs_summary)
            
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = f"[-] Engine Error: {error_msg}"
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)