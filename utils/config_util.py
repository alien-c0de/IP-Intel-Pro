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
     COMPANY_NAME = config['General']['COMPANY_NAME']
     TOOL_NAME = config['General']['TOOL_NAME']
     EMAIL = config['General']['EMAIL']
     GITHUB = config['General']['GITHUB']
     FOOTER_OWNER = config['General']['FOOTER_OWNER']
     REPORT_TITLE = config['General']['REPORT_TITLE']
     REPORT_SUB_TITLE = config['General']['REPORT_SUB_TITLE']
     REPORT_FILE_NAME = config['General']['REPORT_FILE_NAME']
     WKHTMLTOPDF = config['General']['WKHTMLTOPDF']

     'VirusTotal' in config
     VIRUS_TOTAL_API_KEY = config['VirusTotal']['API_KEY']   
     VIRUS_TOTAL_ENDPOINT_URL = config['VirusTotal']['ENDPOINT_URL'] 
     VIRUS_TOTAL_REPORT_LINK = config['VirusTotal']['REPORT_LINK']  
     VIRUS_TOTAL_REPORT_FILE_NAME = config['VirusTotal']['FILE_NAME']
     
     'MetaDefender' in config
     META_DEFENDER_API_KEY = config['MetaDefender']['API_KEY']
     META_DEFENDER_ENDPOINT_URL = config['MetaDefender']['ENDPOINT_URL']
     META_DEFENDER_REPORT_FILE_NAME = config['MetaDefender']['FILE_NAME']
     
     'AbuseIPDB' in config
     ABUSEIPDB_API_KEY = config['AbuseIPDB']['API_KEY']
     ABUSEIPDB_ENDPOINT_URL = config['AbuseIPDB']['ENDPOINT_URL']
     ABUSEIPDB_REPORT_FILE_NAME = config['AbuseIPDB']['FILE_NAME']
     
     'AlienVault_OTX' in config
     ALIENVAULT_OTX_API_KEY = config['AlienVault_OTX']['API_KEY']
     ALIENVAULT_OTX_ENDPOINT_URL = config['AlienVault_OTX']['ENDPOINT_URL']
     ALIENVAULT_OTX_REPORT_FILE_NAME = config['AlienVault_OTX']['FILE_NAME']
     
     'GreyNoise' in config
     GREYNOISE_API_KEY = config['GreyNoise']['API_KEY']
     GREYNOISE_ENDPOINT_URL = config['GreyNoise']['ENDPOINT_URL']
     GREYNOISE_REPORT_FILE_NAME = config['GreyNoise']['FILE_NAME']

     'IPQualityScore' in config
     IPQUALITYSCORE_API_KEY = config['IPQualityScore']['API_KEY']
     IPQUALITYSCORE_ENDPOINT_URL = config['IPQualityScore']['ENDPOINT_URL']
     IPQUALITYSCORE_REPORT_FILE_NAME = config['IPQualityScore']['FILE_NAME']

     'CISCO_Talos' in config
     TALOS_ENDPOINT_URL = config['CISCO_Talos']['ENDPOINT_URL']
     TALOS_REFERER = config['CISCO_Talos']['REFERER']
     TALOS_REPORT_FILE_NAME = config['CISCO_Talos']['FILE_NAME']

     'CriminalIP' in config
     CRIMINAL_IP_API_KEY = config['CriminalIP']['API_KEY']
     CRIMINAL_IP_ENDPOINT_URL = config['CriminalIP']['ENDPOINT_URL']
     CRIMINAL_IP_REPORT_FILE_NAME = config['CriminalIP']['FILE_NAME']