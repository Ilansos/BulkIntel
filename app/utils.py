import requests
import re
import json
import os
import base64
import logging
import sys
import concurrent.futures

logging.basicConfig(stream=sys.stdout, 
                    level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Replace these with your actual API keys and secure them appropriately
ABUSEIPDB_KEYS = [
    os.environ['ABUSEIPDB_KEY'],
    os.environ['ABUSEIPDB_KEY1'],
    os.environ['ABUSEIPDB_KEY2']
]

# Counter to keep track of the request number
request_counter = 0

VIRUSTOTAL_KEY = os.environ['VIRUSTOTAL_KEY']
IBM_XFORCE_KEY = os.environ['IBM_XFORCE_KEY']
IBM_XFORCE_PASSWORD = os.environ['IBM_XFORCE_PASSWORD']
BIG_DATA_USERAGENT_KEY = os.environ['BIG_DATA_USERAGENT_KEY']

categories_data = {}
country_codes_dict = {}

def get_api_key():
    global request_counter
    api_key = ABUSEIPDB_KEYS[request_counter % len(ABUSEIPDB_KEYS)]
    request_counter += 1
    return api_key

def load_global_data():
    # Assuming you have categories.json and country_codes.json in your Django settings directory or a similar secure place
    
    global categories_data, country_codes_dict
    try:
        with open('app/config_files/categories.json', 'r') as file:
            categories_data = {int(k): v for k, v in json.load(file).items()}
        with open('app/config_files/country_codes.json', 'r') as file:
            country_codes_dict = json.load(file)
        logger.info("Successfully loaded global data")
    except Exception as e:
        logger.error(f"Failed to load global data: {e}")

load_global_data()

def extract_ips(data):
    return re.findall(r'(?:\d{1,3}\.){3}\d{1,3}|(?:[A-Fa-f0-9]{1,4}:+)+[A-Fa-f0-9]{0,4}', data)

def check_ip_on_abuse_ipdb(abuse_ipdb_key, country_codes_dict, ip):
        url = f'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Key': abuse_ipdb_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        params = {
            'ipAddress': ip,
            'maxAgeInDays': '30',
        }
        # logging.info(f"Requesting AbuseIPDB check for IP: {ip}")
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json().get("data")
            countrycode = data.get("countryCode")
            isp = data.get("isp")
            total_reports = data.get("totalReports")
            abuseConfidenceScore = data.get("abuseConfidenceScore")
            try:
                isWhitelisted = data.get("isWhitelisted")
                if isWhitelisted is None:
                    isWhitelisted = "False"
            except:
                isWhitelisted = "False"
            country = country_codes_dict.get(countrycode)
        else: 
            logger.error(f"Failed to fetch data for IP {ip}. Status code: {response.status_code}")
        return country, isp, total_reports, abuseConfidenceScore, isWhitelisted

def check_reports_on_abuse_ipdb(abuse_ipdb_key, ip):
    global categories_data
    url = f'https://api.abuseipdb.com/api/v2/reports'
    headers = {
        'Key': abuse_ipdb_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    params = {
        'ipAddress': ip,
        'maxAgeInDays': '30',
        'perPage':'1'
    }
    translated_category = "Unknown Category"
    reportedAt = "Unknown Date"
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json().get("data")
        category = data.get('results', [{}])[0].get('categories', [])[0]
        reportedAt = data.get('results', [{}])[0].get('reportedAt')
        if category in categories_data:
            translated_category = categories_data[category]
        else:
            logger.error(f"Report Category not found for IP {ip}")
    else:
        logger.error(f"Failed to fetch data for IP {ip}. Status code: {response.status_code}")
    return translated_category, reportedAt

# def abuse_ipdb_logic(ips_to_check):
#     abuse_ipdb_key = get_api_key()
#     global categories_data, country_codes_dict
#     ip_info = []
#     for ip in ips_to_check:
#         try:
#             country, isp, total_reports, abuseConfidenceScore, isWhitelisted = check_ip_on_abuse_ipdb(abuse_ipdb_key, country_codes_dict, ip)
            
#             output_line = f"{ip} ({country}, {isp}) "
            
#             if total_reports >= 1:
#                 translated_category, reportedAt = check_reports_on_abuse_ipdb(abuse_ipdb_key, ip)
#                 output_line += f"Reported for {translated_category} at {reportedAt}"
#             else:
#                 output_line += "No reports"

#             output_line += f" | Abuse Confidence Score: {abuseConfidenceScore} | Is Whitelisted: {isWhitelisted}"

#             ip_info.append(output_line)

#         except:
#             ip_info.append(f"Error requesting the IP {ip}")
#     return ip_info

def abuse_ipdb_logic(ips_to_check):
    abuse_ipdb_key = get_api_key()
    global categories_data, country_codes_dict
    ip_info = []

    # Function to process each IP
    def process_ip(ip):
        try:
            country, isp, total_reports, abuseConfidenceScore, isWhitelisted = check_ip_on_abuse_ipdb(abuse_ipdb_key, country_codes_dict, ip)
            
            output_line = f"{ip} ({country}, {isp}) "
            
            if total_reports >= 1:
                translated_category, reportedAt = check_reports_on_abuse_ipdb(abuse_ipdb_key, ip)
                output_line += f"Reported for {translated_category} at {reportedAt}"
            else:
                output_line += "No reports"

            output_line += f" | Abuse Confidence Score: {abuseConfidenceScore} | Is Whitelisted: {isWhitelisted}"

            return output_line

        except Exception as e:
            return f"Error requesting the IP {ip}: {str(e)}"

    # Using ThreadPoolExecutor for concurrent execution
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit each IP for processing concurrently
        futures = [executor.submit(process_ip, ip) for ip in ips_to_check]

        # Gather results
        for future in concurrent.futures.as_completed(futures):
            ip_info.append(future.result())

    return ip_info

def check_ip_on_virustotal(ip):
    virus_key = VIRUSTOTAL_KEY
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
    "accept": "application/json",
    "x-apikey": f"{virus_key}"
    }
    response = requests.get(url, headers=headers)
    logger.info(f"Requesting VirusTotal check for IP: {ip}")

    if response.status_code == 200:
        data = response.json().get("data")
        isp = data.get("attributes").get("as_owner")
        countrycode = data.get("attributes").get("country")
        malicious_count = data.get("attributes").get("last_analysis_stats").get("malicious")
    else:
        logger.error(f"Failed to fetch reports for IP {ip}. Status code: {response.status_code}")
        logger.error(f"Failed to fetch data for IP {ip}. Status code: {response.status_code}")  
    return countrycode, isp, malicious_count

def virustotal_logic(ips_to_check):
    logger.info("Starting virustotal_logic")
    ip_info = []
    
    for ip in ips_to_check:
        try:
            country, isp, malicious_count = check_ip_on_virustotal(ip)
            output_line = f"{ip} ({country}, {isp}) "
            
            if malicious_count >= 1:
                output_line += f"On VirusTotal {malicious_count} security vendors flagged this IP address as malicious"
            else:
                output_line += "No reports on VirusTotal"
            
            ip_info.append(output_line)
        except:
            ip_info.append(f"Error requesting the IP {ip}")
    return ip_info

def auth_token_ibm():
    ibm_xforce_key = IBM_XFORCE_KEY
    ibm_xforce_password = IBM_XFORCE_PASSWORD

    # Encode the API key and password using base64
    credentials = base64.b64encode(f'{ibm_xforce_key}:{ibm_xforce_password}'.encode('utf-8')).decode('utf-8')
    return credentials

def get_ip_risk_ibm(ip, token):
    url = f'https://api.xforce.ibmcloud.com/api/ipr/{ip}'
    # Set up the headers with encoded credentials
    headers = {
        'Authorization': f'Basic {token}',
        'Content-Type': 'application/json',
    }

    # Make the request
    response = requests.get(url, headers=headers)
    logger.info(f"Requesting IBM Risk check for IP: {ip}")
    # Check the response
    if response.status_code == 200:
        data = response.json()
        score = data.get('score')
    else:
        logger.error(f"Failed to fetch reports for IP {ip}. Status code: {response.status_code}")

    return ip, score

def get_ip_whois_ibm(ip, token):
    url = f"https://api.xforce.ibmcloud.com/api/whois/{ip}"
    # Set up the headers with encoded credentials
    headers = {
        'Authorization': f'Basic {token}',
        'Content-Type': 'application/json',
    }

    # Make the request
    response = requests.get(url, headers=headers)
    logger.info(f"Requesting whois IBM X-Force check for IP {ip}")
    # Check the response
    if response.status_code == 200:
        data = response.json()
        contact = data.get('contact')
        organization = contact[0].get('organization')
        country = contact[0].get('country')
    else:
        logger.error(f"Failed to fetch reports for IP {ip}. Status code: {response.status_code}")

    return organization, country

def ibm_xforce_logic(ips_to_check):
    logger.info("Starting ibm_xforce_logic")
    token = auth_token_ibm()
    ip_info = []
    for ip_address in ips_to_check:
        ip, score = get_ip_risk_ibm(ip_address, token)
        isp, country = get_ip_whois_ibm(ip_address, token)
        output_line = f"{ip}, ({country}, {isp}) Risk Score of {score} in IBM X-Force"
        ip_info.append(output_line)
    return ip_info

def extract_domains(data):
    # Split the input by lines and strip any surrounding whitespace
    domains = [line.strip() for line in data.splitlines() if line.strip()]
    return domains

def get_domain_report(domains):
    domains_info = []
    for domain in domains:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_KEY
        }

        response = requests.get(url, headers=headers)
        response_json = response.json()
        try:
            data = response_json.get("data")
            id = data.get("id")
            attributes = data.get("attributes")
            last_analysis = attributes.get("last_analysis_stats")
            malicious = last_analysis.get("malicious")
            suspicious = last_analysis.get("suspicious")
            undetected = last_analysis.get("undetected")
            harmless = last_analysis.get("harmless")
            total_count = malicious + suspicious + undetected + harmless
            if malicious == 0 and suspicious == 0:
                report = f"Domain {id}: On VirusTotal no security vendors flagged this domain as malicious"
            elif malicious == 0 and suspicious >= 1:
                report = f"Domain {id}: On VirusTotal {suspicious}/{total_count} security vendors flagged this domain as suspicious"
            else:
                report = f"Domain {id}: On VirusTotal {malicious}/{total_count} security vendors flagged this domain as malicious"
            domains_info.append(report)
        except:
            domains_info.append(f"Error requesting the domain {domain}")
    
    return domains_info

def get_user_agent_info(user_agents_raw):
    url = "https://api-bdc.net/data/user-agent-info"
    user_agents_strings = []
    for user_agent_raw in user_agents_raw:
        params = {
            'userAgentRaw': user_agent_raw,
            'key': BIG_DATA_USERAGENT_KEY
        }

        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            try: 
                response_json = response.json()
                device = response_json.get('device')
                os = response_json.get('os')
                user_agent = response_json.get('userAgent')
                is_spider = response_json.get('isSpider')
                if is_spider == True:
                    is_spider = "Yes"
                else:
                    is_spider = "No"
                is_mobile = response_json.get("isMobile")
                if is_mobile == True:
                    is_mobile = "Yes"
                else:
                    is_mobile = "No"
                
                return_string = f"User agent: {user_agent} | Device: {device} | OS: {os} | Bot: {is_spider} | Mobile user agent: {is_mobile}"
                user_agents_strings.append(return_string)
            except:
                user_agents_strings.append(f"Error requesting user agent: {user_agent_raw}")
        else:
            user_agents_strings.append(f"Error requesting user agent: {user_agent_raw}")

    return user_agents_strings

def scan_url_virustotal(urls_to_scan):
    urls_info = []
    for url_to_scan in urls_to_scan:
        url = "https://www.virustotal.com/api/v3/urls"

        payload = { "url": url_to_scan }
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_KEY,
            "content-type": "application/x-www-form-urlencoded"
        }

        response = requests.post(url, data=payload, headers=headers)
        response_json = response.json()
        data = response_json.get("data")
        scan_id = data.get('id')
        report = get_url_analisis(url_to_scan, scan_id)
        urls_info.append(report)

    return urls_info

def get_url_analisis(url_to_scan, scan_id):

    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"

    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_KEY
    }

    response = requests.get(url, headers=headers)
    try:
        response_json = response.json()
        data = response_json.get("data")

        attributes = data.get("attributes")
        stats = attributes.get("stats")
        malicious = stats.get("malicious")
        suspicious = stats.get("suspicious")
        undetected = stats.get("undetected")
        harmless = stats.get("harmless")
        total_count = malicious + suspicious + undetected + harmless

        if malicious == 0 and suspicious == 0:
            report = f"URL {url_to_scan}: On VirusTotal no security vendors flagged this URL as malicious"
        elif malicious == 0 and suspicious >= 1:
            report = f"URL {url_to_scan}: On VirusTotal {suspicious}/{total_count} security vendors flagged URL domain as suspicious"
        else:
            report = f"URL {url_to_scan}: On VirusTotal {malicious}/{total_count} security vendors flagged URL domain as malicious"
    except:
        report = f"Error requesting the URL {url_to_scan}"

    return report