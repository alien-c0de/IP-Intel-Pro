import os
import time
import pdfkit
from colorama import Fore, Style
from utils.config_util import Configuration

class HTML_util:

    def __init__(self, html):
        self.__html = html
    
    # Create new folders
    async def __create_dirs(self, root, subfolders=None):
        root = root if subfolders == None else f'{root}/{subfolders}/'
        if not os.path.exists(root):
            os.makedirs(f'{root}', exist_ok=True)

    async def outputHTML(self, timestamp):
        config = Configuration()
        company_name = config.COMPANY_NAME
        report_title  = config.REPORT_TITLE
        report_sub_title = config.REPORT_SUB_TITLE
        
        header = f"""<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{company_name} - IP Reputation Report</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
            <style>
                * {{
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }}
                
                body {{
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
                    background: #f5f5f5;
                    color: #000000;
                    padding: 30px;
                    line-height: 1.6;
                }}
                
                .container {{
                    max-width: 1500px;
                    margin: 0 auto;
                    background: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
                    overflow: hidden;
                }}
                
                .header {{
                    background: #2c2c2c;
                    color: white;
                    padding: 10px 20px;
                    text-align: center;
                }}
                
                .header-content {{
                    max-width: 900px;
                    margin: 0 auto;
                }}
                
                .company-logo {{
                    font-size: 34px;
                    font-weight: 800;
                    margin-bottom: 5px;
                    letter-spacing: -0.5px;
                }}
                
                .company-tagline {{
                    font-size: 14px;
                    font-weight: 500;
                    margin-bottom: 15px;
                    color: #cccccc;
                }}
                
                .report-title {{
                    font-size: 20px;
                    font-weight: 700;
                    margin-top: 10px;
                    border-top: 2px solid #555555;
                    padding-top: 10px;
                }}
                
                .report-subtitle {{
                    font-size: 12px;
                    margin-top: 8px;
                    font-weight: 400;
                    color: #cccccc;
                }}
                
                .meta-info {{
                    background: #f9f9f9;
                    padding: 10px 10px;
                    border-bottom: 1px solid #dddddd;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    flex-wrap: wrap;
                    gap: 15px;
                }}
                
                .timestamp {{
                    display: flex;
                    align-items: right;
                    gap: 8px;
                    color: #333333;
                    font-size: 14px;
                    font-weight: 500;
                }}
                
                .timestamp::before {{
                    content: '🕐';
                    font-size: 18px;
                }}
                
                .status-badge {{
                    background: #4a4a4a;
                    color: white;
                    padding: 8px 20px;
                    border-radius: 4px;
                    font-size: 13px;
                    font-weight: 600;
                    margin-left: 20px;
                }}
                
                .content {{
                    padding: 10px 30px;
                }}
                
                .section {{
                    margin-bottom: 20px;
                }}
                
                .section-header {{
                    background: #5f5e5e;
                    color: white;
                    padding: 10px 20px;
                    border-radius: 0;
                    font-size: 18px;
                    font-weight: 700;
                    text-align: center;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 12px;
                }}
                
                .section-header::before {{
                    content: '🔍';
                    font-size: 24px;
                }}
                
                .section-header.virustotal::before {{
                    content: '🛡️';
                }}
                
                .section-header.metadefender::before {{
                    content: '🔒';
                }}
                
                .section-header.abuseipdb::before {{
                    content: '⚠️';
                }}
                
                .section-body {{
                    background: #ffffff;
                    border: 1px solid #cccccc;
                    border-top: none;
                    padding: 15px;
                }}
                
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 15px;
                    background: white;
                    border: 1px solid #cccccc;
                }}
                
                table:last-child {{
                    margin-bottom: 0;
                }}
                
                thead {{
                    background: #f0f0f0;
                }}
                
                th {{
                    text-align: center;
                    padding: 14px 16px;
                    font-weight: 700;
                    font-size: 14px;
                    color: #000000;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    border: 1px solid #cccccc;
                    background: #e8e8e8;
                }}
                
                tr {{
                    border: 1px solid #cccccc;
                }}
                
                tbody tr {{
                    border: 1px solid #cccccc;
                    background: #ffffff;
                }}
                
                tbody tr:nth-child(even) {{
                    background: #f9f9f9;
                }}
                
                td {{
                    padding: 12px 16px;
                    font-size: 14px;
                    color: #333333;
                    vertical-align: top;
                    border: 1px solid #cccccc;
                }}
                
                td:first-child {{
                    font-weight: 600;
                    color: #000000;
                    width: 25%;
                    background: #f5f5f5;
                    min-width: 100px;
                }}
                
                /* Specific styling for multi-column tables (like MetaDefender) */
                table thead th:not(:first-child) {{
                    width: auto;
                    min-width: 100px;
                }}
                
                table tbody td {{
                    hyphens: auto;
                }}
                
                /* Force long strings to break */
                table td {{
                    overflow-wrap: anywhere;
                }}
                
                a {{
                    color: #333333;
                    text-decoration: underline;
                    font-weight: 500;
                }}
                
                a:hover {{
                    color: #000000;
                }}
                
                .threat-badge {{
                    display: inline-block;
                    padding: 4px 12px;
                    border-radius: 4px;
                    font-weight: 700;
                    font-size: 12px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }}
                
                .malicious {{
                    background: #333333;
                    color: #ffffff;
                    font-weight: 700;
                }}
                
                .malware {{
                    background: #4a4a4a;
                    color: #ffffff;
                    font-weight: 700;
                }}
                
                .suspicious {{
                    background: #666666;
                    color: #ffffff;
                    font-weight: 700;
                }}
                
                .undetected {{
                    background: #cccccc;
                    color: #000000;
                }}
                
                .unrated {{
                    background: #cccccc;
                    color: #000000;
                }}
                
                .harmless {{
                    background: #e8e8e8;
                    color: #000000;
                    font-weight: 700;
                }}
                
                .clean {{
                    background: #f5f5f5;
                    color: #000000;
                    font-weight: 700;
                }}
                
                .footer {{
                    background: #2c2c2c;
                    color: white;
                    text-align: center;
                    padding: 15px 20px;
                    font-size: 14px;
                    font-weight: 500;
                }}
                
                .footer-content {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    flex-wrap: wrap;
                    gap: 15px;
                }}
                
                .footer-left {{
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }}
                
                .footer-right {{
                    opacity: 0.8;
                }}
                
                @media print {{
                    body {{
                        background: white;
                        padding: 0;
                    }}
                    
                    .container {{
                        box-shadow: none;
                    }}
                    
                    table {{
                        table-layout: auto;
                    }}
                }}
                
                @media (max-width: 768px) {{
                    body {{
                        padding: 15px;
                    }}
                    
                    .header, .content {{
                        padding: 25px 15px;
                    }}
                    
                    .meta-info {{
                        padding: 15px;
                    }}
                    
                    .footer-content {{
                        flex-direction: column;
                        text-align: center;
                    }}
                    
                    td:first-child {{
                        width: 35%;
                        min-width: 60px;
                    }}
                    
                    td {{
                        font-size: 12px;
                        padding: 8px 6px;
                        max-width: 120px;
                    }}
                    
                    th {{
                        font-size: 11px;
                        padding: 8px 6px;
                    }}
                    
                    .section-body {{
                        padding: 10px;
                        overflow-x: auto;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="header-content">
                        <div class="company-logo">{company_name}</div>
                        <div class="company-tagline">🔐 Security Intelligence & Threat Analysis Platform</div>
                        <div class="report-title">{report_title}</div>
                        <div class="report-subtitle">{report_sub_title}</div>
                    </div>
                </div>
                
                <div class="meta-info">
                    <div class="timestamp">Generated: {time.strftime('%A, %B %d, %Y at %I:%M:%S %p', time.localtime(time.time()))}</div>
                </div>
                
                <div class="content">
        """
        
        footer = f"""
                </div>
                
                <div class="footer">
                    <div class="footer-content">
                        <div class="footer-left">
                            <span>© {config.YEAR} {company_name}</span>
                            <span>•</span>
                            <span>All Rights Reserved</span>
                        </div>
                        <div class="footer-right">
                            Developed by {config.AUTHOR} | Version {config.VERSION}
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                // Color-code threat levels in table cells
                const tdElements = document.querySelectorAll("td");
                
                function highlightThreats() {{
                    tdElements.forEach(td => {{
                        let html = td.innerHTML;
                        let textContent = td.textContent.toLowerCase();
                        
                        // Check if cell contains threat keywords and apply colors
                        if (textContent.includes('malicious')) {{
                            html = html.replace(/\bmalicious\b/gi, '<span style="color:#dc2626;font-weight:700;">MALICIOUS</span>');
                        }}
                        if (textContent.includes('malware')) {{
                            html = html.replace(/\bmalware\b/gi, '<span style="color:#dc2626;font-weight:700;">MALWARE</span>');
                        }}
                        if (textContent.includes('suspicious')) {{
                            html = html.replace(/\bsuspicious\b/gi, '<span style="color:#f97316;font-weight:700;">SUSPICIOUS</span>');
                        }}
                        if (textContent.includes('undetected')) {{
                            html = html.replace(/\bundetected\b/gi, '<span style="color:#6b7280;">UNDETECTED</span>');
                        }}
                        if (textContent.includes('unrated')) {{
                            html = html.replace(/\bunrated\b/gi, '<span style="color:#6b7280;">UNRATED</span>');
                        }}
                        if (textContent.includes('harmless')) {{
                            html = html.replace(/\bharmless\b/gi, '<span style="color:#059669;font-weight:700;">HARMLESS</span>');
                        }}
                        if (textContent.includes('clean')) {{
                            html = html.replace(/\bclean\b/gi, '<span style="color:#059669;font-weight:700;">CLEAN</span>');
                        }}
                        
                        td.innerHTML = html;
                    }});
                }}
                
                // Color-code Category and Result columns in VirusTotal tables
                function colorCodeCategories() {{
                    const allTables = document.querySelectorAll('table');
                    
                    allTables.forEach(table => {{
                        const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.trim().toLowerCase());
                        const categoryIndex = headers.indexOf('category');
                        const resultIndex = headers.indexOf('result');
                        
                        if (categoryIndex !== -1 || resultIndex !== -1) {{
                            const rows = table.querySelectorAll('tbody tr');
                            
                            rows.forEach(row => {{
                                const cells = row.querySelectorAll('td');
                                
                                // Color code Category column
                                if (categoryIndex !== -1 && cells[categoryIndex]) {{
                                    const categoryCell = cells[categoryIndex];
                                    const categoryText = categoryCell.textContent.trim().toLowerCase();
                                    
                                    if (categoryText === 'malicious') {{
                                        categoryCell.style.color = '#dc2626';
                                        categoryCell.style.fontWeight = '700';
                                        categoryCell.style.backgroundColor = '#fee2e2';
                                    }} else if (categoryText === 'suspicious') {{
                                        categoryCell.style.color = '#f97316';
                                        categoryCell.style.fontWeight = '700';
                                        categoryCell.style.backgroundColor = '#ffedd5';
                                    }} else if (categoryText === 'harmless' || categoryText === 'clean') {{
                                        categoryCell.style.color = '#059669';
                                        categoryCell.style.fontWeight = '700';
                                        categoryCell.style.backgroundColor = '#d1fae5';
                                    }} else if (categoryText === 'undetected') {{
                                        categoryCell.style.color = '#6b7280';
                                        categoryCell.style.backgroundColor = '#f3f4f6';
                                    }}
                                }}
                                
                                // Color code Result column
                                if (resultIndex !== -1 && cells[resultIndex]) {{
                                    const resultCell = cells[resultIndex];
                                    const resultText = resultCell.textContent.trim().toLowerCase();
                                    
                                    if (resultText.includes('malicious') || resultText.includes('malware')) {{
                                        resultCell.style.color = '#dc2626';
                                        resultCell.style.fontWeight = '700';
                                        resultCell.style.backgroundColor = '#fee2e2';
                                    }} else if (resultText.includes('suspicious')) {{
                                        resultCell.style.color = '#f97316';
                                        resultCell.style.fontWeight = '700';
                                        resultCell.style.backgroundColor = '#ffedd5';
                                    }} else if (resultText.includes('clean') || resultText === 'harmless') {{
                                        resultCell.style.color = '#059669';
                                        resultCell.style.fontWeight = '700';
                                        resultCell.style.backgroundColor = '#d1fae5';
                                    }} else if (resultText === 'undetected' || resultText === 'unrated') {{
                                        resultCell.style.color = '#6b7280';
                                        resultCell.style.backgroundColor = '#f3f4f6';
                                    }}
                                }}
                            }});
                        }}
                    }});
                }}
                
                // Wrap sections with proper styling
                function wrapSections() {{
                    const tables = document.querySelectorAll('.content > table, .content > h2 + table');
                    let currentSection = null;
                    let sectionType = '';
                    
                    tables.forEach((table, index) => {{
                        // Check if previous element is h2
                        const prevElement = table.previousElementSibling;
                        
                        if (prevElement && prevElement.tagName === 'H2') {{
                            // Close previous section if exists
                            if (currentSection) {{
                                table.parentNode.insertBefore(currentSection, table);
                            }}
                            
                            // Create new section
                            const sectionTitle = prevElement.textContent.trim();
                            currentSection = document.createElement('div');
                            currentSection.className = 'section';
                            
                            // Determine section type
                            if (sectionTitle.includes('VirusTotal')) {{
                                sectionType = 'virustotal';
                            }} else if (sectionTitle.includes('MetaDefender')) {{
                                sectionType = 'metadefender';
                            }} else if (sectionTitle.includes('AbuseIPDB')) {{
                                sectionType = 'abuseipdb';
                            }} else {{
                                sectionType = '';
                            }}
                            
                            // Create section header
                            const header = document.createElement('div');
                            header.className = `section-header ${{sectionType}}`;
                            header.textContent = sectionTitle;
                            
                            // Create section body
                            const body = document.createElement('div');
                            body.className = 'section-body';
                            
                            currentSection.appendChild(header);
                            currentSection.appendChild(body);
                            
                            // Remove the h2
                            prevElement.remove();
                        }}
                        
                        // Add table to current section body
                        if (currentSection) {{
                            const sectionBody = currentSection.querySelector('.section-body');
                            sectionBody.appendChild(table.cloneNode(true));
                            table.remove();
                        }}
                    }});
                    
                    // Insert last section if exists
                    if (currentSection) {{
                        document.querySelector('.content').appendChild(currentSection);
                    }}
                }}
                
                // Run on page load
                document.addEventListener('DOMContentLoaded', function() {{
                    wrapSections();
                    highlightThreats();
                    colorCodeCategories();
                }});
                
                // Fallback if DOMContentLoaded already fired
                if (document.readyState === 'complete' || document.readyState === 'interactive') {{
                    setTimeout(function() {{
                        wrapSections();
                        highlightThreats();
                        colorCodeCategories();
                    }}, 100);
                }}
            </script>
        </body>
        </html>
        """
        
        # Create output directory
        await self.__create_dirs('output')
        
        # Generate file names
        html_report = "%s_%s.html" % (config.REPORT_FILE_NAME, timestamp.strftime("%d%b%Y_%H-%M-%S"))
        pdf_report = "%s_%s.pdf" % (config.REPORT_FILE_NAME, timestamp.strftime("%d%b%Y_%H-%M-%S"))
        # file_name_html = '%s_%s.html' % (file_name.replace("/", "_"), timestamp)
        # file_name_pdf = '%s_%s.pdf' % (file_name.replace("/", "_"), timestamp)
        
        html_report = os.path.join('./output', html_report)
        pdf_report = os.path.join('./output', pdf_report)

        # Write HTML file
        with open(html_report, "w", encoding='UTF-8') as f: 
            f.write(header)
            for x in self.__html:
                f.write(x)
            f.write(footer)

        # filenameH = file_name_html.partition("output/")[-1]
        filenameH = os.path.basename(html_report)
        print(Fore.GREEN + Style.BRIGHT + f"\n[+] HTML Report" + Fore.WHITE + Style.BRIGHT, filenameH, Fore.GREEN + Style.BRIGHT + "is Ready", Fore.RESET)

        # Create PDF file from HTML file
        try:
            options = {
                'page-size': 'A4',
                'margin-top': '0.30in',
                'margin-right': '0.60in',
                'margin-bottom': '0.30in',
                'margin-left': '0.60in',
                'footer-right': '[page]',
                'encoding': "UTF-8",
                'enable-local-file-access': None,
                'custom-header': [('Accept-Encoding', 'gzip')]
            }
            
            filenameP = os.path.basename(pdf_report)
            
            wkhtmltopdf_path = config.WKHTMLTOPDF
            if os.name == 'nt':
                pdf_config = pdfkit.configuration(wkhtmltopdf = wkhtmltopdf_path)
                pdfkit.from_file(html_report, pdf_report, options=options, configuration=pdf_config)
            else:
                pdfkit.from_file(html_report, pdf_report, options=options)
                
            print(Fore.GREEN + Style.BRIGHT + f"[+] PDF Report" + Fore.WHITE + Style.BRIGHT, filenameP, Fore.GREEN + Style.BRIGHT + "is Ready", Fore.RESET)
            
        except Exception as ex:
            print(Fore.YELLOW + Style.BRIGHT + f"[!] PDF generation failed: {str(ex)}" + Fore.RESET)
            print(Fore.YELLOW + Style.BRIGHT + f"[!] HTML report is available at: {filenameH}\n" + Fore.RESET)