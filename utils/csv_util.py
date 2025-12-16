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
            # talos_lst = args[9] if len(args) > 9 else []
            
            file_name = "Final_Summary"

            ips = []            
            if isFile:
                with open(target_url, "r") as url_file:
                    for url in url_file.readlines():
                        ips.append(url.strip())
                    ips = list(ips)
            else:
                ips = list(target_url.split(",")) 

            ips_dt = pd.DataFrame(ips, columns=['IP Address'])

            # VirusTotal
            vt_err_code = str(vt_lst[0]) if vt_lst else ""
            if 'Quota exceeded' in vt_err_code or 'Error' in vt_err_code:
                vt_dt = pd.DataFrame(vt_lst[0], columns=['VirusTotal Error'])
            else: 
                vt_dt = pd.DataFrame(vt_lst, columns=['VirusTotal Malicious Score']) 

            # AbuseIPDB
            abs_err_code = str(abs_lst[0]) if abs_lst else ""
            if '429' in abs_err_code or 'Error' in abs_err_code:
                abs_dt = pd.DataFrame(abs_lst[0], columns=['AbuseIPDB Error'])
            else: 
                abs_dt = pd.DataFrame(abs_lst, columns=['AbuseIPDB Confidence Score']) 

            # MetaDefender
            meta_err_code = str(meta_lst[0]) if meta_lst else ""
            if '429000' in meta_err_code or 'Error' in meta_err_code:
                meta_dt = pd.DataFrame(meta_lst[0], columns=['MetaDefender Error'])
            else: 
                meta_dt = pd.DataFrame(meta_lst, columns=['MetaDefender Score', 'Geo Info']) 

            # AlienVault OTX
            if otx_lst:
                otx_err_code = str(otx_lst[0]) if otx_lst else ""
                if 'Error' in otx_err_code:
                    otx_dt = pd.DataFrame(otx_lst[0], columns=['AlienVault OTX Error'])
                else:
                    otx_dt = pd.DataFrame(otx_lst, columns=['AlienVault Reputation Score'])
            else:
                otx_dt = pd.DataFrame([['N/A']] * len(ips), columns=['AlienVault Reputation Score'])

            # GreyNoise
            if gn_lst:
                gn_err_code = str(gn_lst[0]) if gn_lst else ""
                if 'Error' in gn_err_code:
                    gn_dt = pd.DataFrame(gn_lst[0], columns=['GreyNoise Error'])
                else:
                    gn_dt = pd.DataFrame(gn_lst, columns=['GN Classification', 'GN Service Name'])
            else:
                gn_dt = pd.DataFrame([['N/A', 'N/A']] * len(ips), columns=['GN Classification', 'GN Service Name'])

            # IPQualityScore
            if ipqs_lst:
                ipqs_err_code = str(ipqs_lst[0]) if ipqs_lst else ""
                if 'Error' in ipqs_err_code:
                    ipqs_dt = pd.DataFrame(ipqs_lst[0], columns=['IPQualityScore Error'])
                else:
                    ipqs_dt = pd.DataFrame(ipqs_lst, columns=['IPQS Fraud Score', 'IPQS ISP'])
            else:
                ipqs_dt = pd.DataFrame([['N/A', 'N/A']] * len(ips), columns=['IPQS Fraud Score', 'IPQS ISP'])

            # # Cisco Talos
            # if talos_lst:
            #     talos_err_code = str(talos_lst[0]) if talos_lst else ""
            #     if 'Error' in talos_err_code:
            #         talos_dt = pd.DataFrame(talos_lst[0], columns=['Cisco Talos Error'])
            #     else:
            #         talos_dt = pd.DataFrame(talos_lst, columns=['Talos Reputation', 'Talos Category'])
            # else:
            #     talos_dt = pd.DataFrame([['N/A', 'N/A']] * len(ips), columns=['Talos Reputation', 'Talos Category'])

            # Combine all dataframes
            # final_df = pd.concat([ips_dt, vt_dt, abs_dt, meta_dt, otx_dt, gn_dt, ipqs_dt, talos_dt], axis=1)
            final_df = pd.concat([ips_dt, vt_dt, abs_dt, meta_dt, otx_dt, gn_dt, ipqs_dt], axis=1)

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