import pandas as pd
import os
from colorama import Fore, Style
from utils.config_util import Configuration

class CSV_util:

    def __init__(self) -> None:
        pass

    async def create_csv(self, *args):
        config = Configuration()
        try:
            timestamp = args[0]
            target_url = args[1]
            isFile = bool(args[2])
            vt_lst = args[3]
            abs_lst = args[4]
            meta_lst = args[5]
            otx_lst = args[6] if len(args) > 6 else []
            gn_lst = args[7] if len(args) > 7 else []
            ipqs_lst = args[8] if len(args) > 8 else []
            crip_lst = args[9] if len(args) > 9 else []
            
            file_name = "Final_Summary"

            # Get IP list
            ips = []            
            if isFile:
                with open(target_url, "r") as url_file:
                    for url in url_file.readlines():
                        ips.append(url.strip())
            else:
                ips = list(target_url.split(","))
            
            num_ips = len(ips)
            ips_dt = pd.DataFrame(ips, columns=['IP Address'])

            # Helper function to normalize data lists
            def normalize_list(data_list, num_ips, columns, default_values):
                """Normalize data list to match number of IPs, handling errors"""
                if not data_list or len(data_list) == 0:
                    # No data at all - fill with N/A
                    return pd.DataFrame([[default_val for default_val in default_values]] * num_ips, columns=columns)
                
                # Check if first element indicates an error for all IPs
                first_elem = str(data_list[0]) if data_list else ""
                if len(data_list) == 1 and ('Error' in first_elem or 'error' in first_elem.lower()):
                    # Single error applies to all IPs
                    return pd.DataFrame([[first_elem] + ['N/A'] * (len(columns) - 1)] * num_ips, columns=columns)
                
                # Data list has mixed or all successful results
                normalized_data = []
                for i in range(num_ips):
                    if i < len(data_list):
                        row_data = data_list[i]
                        # Check if this specific row is an error
                        if isinstance(row_data, list):
                            # Check if any element in the list indicates an error
                            row_str = str(row_data)
                            if 'Error' in row_str or 'error' in row_str.lower():
                                # This row has an error - keep it as is
                                # Pad with N/A if needed
                                while len(row_data) < len(columns):
                                    row_data.append('N/A')
                                normalized_data.append(row_data[:len(columns)])
                            else:
                                # Normal data row
                                while len(row_data) < len(columns):
                                    row_data.append('N/A')
                                normalized_data.append(row_data[:len(columns)])
                        else:
                            # Single value
                            normalized_data.append([row_data] + ['N/A'] * (len(columns) - 1))
                    else:
                        # Missing data for this IP - fill with default
                        normalized_data.append(list(default_values))
                
                return pd.DataFrame(normalized_data, columns=columns)

            # VirusTotal
            vt_dt = normalize_list(vt_lst, num_ips, 
                                   ['VirusTotal Malicious Score', 'VirusTotal Suspicious Score'], 
                                   ['N/A', 'N/A'])

            # AbuseIPDB
            abs_dt = normalize_list(abs_lst, num_ips, 
                                    ['AbuseIPDB Confidence Score'], 
                                    ['N/A'])

            # MetaDefender
            meta_dt = normalize_list(meta_lst, num_ips, 
                                     ['MetaDefender Score', 'Geo Info'], 
                                     ['N/A', 'N/A'])

            # AlienVault OTX
            otx_dt = normalize_list(otx_lst, num_ips, 
                                    ['AlienVault Reputation Score'], 
                                    ['N/A'])

            # GreyNoise
            gn_dt = normalize_list(gn_lst, num_ips, 
                                   ['GN Classification', 'GN Service Name'], 
                                   ['N/A', 'N/A'])

            # IPQualityScore
            ipqs_dt = normalize_list(ipqs_lst, num_ips, 
                                     ['IPQS Fraud Score', 'IPQS ISP'], 
                                     ['N/A', 'N/A'])

            # Cisco Talos
            crip_dt = normalize_list(crip_lst, num_ips, 
                                      ['CriminalIP Inbound Score', 'CriminalIP Outbound Score'], 
                                      ['N/A', 'N/A'])

            # Combine all dataframes
            final_df = pd.concat([ips_dt, vt_dt, abs_dt, meta_dt, otx_dt, gn_dt, ipqs_dt, crip_dt], axis=1)

            # Create filename
            file_name_csv = "%s_%s.csv" % (file_name, timestamp.strftime("%d%b%Y_%H-%M-%S"))
            file_name_csv = os.path.join('./output', file_name_csv)
            final_df.to_csv(file_name_csv, index=False, header=True)

            filenameC = os.path.basename(file_name_csv)

            print(Fore.GREEN + Style.BRIGHT + f"[+] CSV Summary" + Fore.WHITE + Style.BRIGHT, filenameC, Fore.GREEN + Style.BRIGHT + f"is Ready\n", Fore.RESET)
        except Exception as ex:
            error_msg = str(ex.args[0]) if ex.args else str(ex)
            msg = "[-] " + "Error: Create CSV, " + error_msg
            print(Fore.RED + Style.BRIGHT + msg + Fore.RESET + Style.RESET_ALL)