import os
from configparser import ConfigParser


class Configuration:
     # Reading Configs
     config = ConfigParser()
     config_path = os.path.join("./config", "config.ini")
     config.read(config_path)
    
     'General' in config
     VERSION = config['General']['VERSION']
     AUTHOR = config['General']['AUTHOR']
     YEAR = config['General']['YEAR']
     EMAIL = config['General']['EMAIL']
     GITHUB = config['General']['GITHUB']
     WKHTMLTOPDF = config['General']['WKHTMLTOPDF']

     'Report Details' in config
     TOOL_NAME = config['Report Details']['TOOL_NAME']
     COMPANY_NAME = config['Report Details']['COMPANY_NAME']
     COMPANY_SLOGAN = config['Report Details']['COMPANY_SLOGAN']
     REPORT_TITLE = config['Report Details']['REPORT_TITLE']
     REPORT_SUB_TITLE = config['Report Details']['REPORT_SUB_TITLE']
     REPORT_FILE_NAME = config['Report Details']['REPORT_FILE_NAME']
     FOOTER_OWNER = config['Report Details']['FOOTER_OWNER']
     REPORT_COPY_RIGHT = config['Report Details']['REPORT_COPY_RIGHT']

     'VirusTotal' in config
     VIRUS_TOTAL_API_KEY = config['VirusTotal']['API_KEY']   
     VIRUS_TOTAL_ENDPOINT_URL = config['VirusTotal']['ENDPOINT_URL'] 
     VIRUS_TOTAL_REPORT_LINK = config['VirusTotal']['REPORT_LINK']  
     
     'MetaDefender' in config
     META_DEFENDER_API_KEY = config['MetaDefender']['API_KEY']
     META_DEFENDER_ENDPOINT_URL = config['MetaDefender']['ENDPOINT_URL']
     
     'AbuseIPDB' in config
     ABUSEIPDB_API_KEY = config['AbuseIPDB']['API_KEY']
     ABUSEIPDB_ENDPOINT_URL = config['AbuseIPDB']['ENDPOINT_URL']
     
     'AlienVault_OTX' in config
     ALIENVAULT_OTX_API_KEY = config['AlienVault_OTX']['API_KEY']
     ALIENVAULT_OTX_ENDPOINT_URL = config['AlienVault_OTX']['ENDPOINT_URL']
     
     'GreyNoise' in config
     GREYNOISE_API_KEY = config['GreyNoise']['API_KEY']
     GREYNOISE_ENDPOINT_URL = config['GreyNoise']['ENDPOINT_URL']

     'IPQualityScore' in config
     IPQUALITYSCORE_API_KEY = config['IPQualityScore']['API_KEY']
     IPQUALITYSCORE_ENDPOINT_URL = config['IPQualityScore']['ENDPOINT_URL']

     'CriminalIP' in config
     CRIMINAL_IP_API_KEY = config['CriminalIP']['API_KEY']
     CRIMINAL_IP_ENDPOINT_URL = config['CriminalIP']['ENDPOINT_URL']

     'CISCO_Talos' in config
     TALOS_ENDPOINT_URL = config['CISCO_Talos']['ENDPOINT_URL']
     TALOS_REFERER = config['CISCO_Talos']['REFERER']