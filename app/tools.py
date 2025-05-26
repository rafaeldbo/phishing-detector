from .constants import GOOGLE_API_KEY
from .constants import BRANDS, TLDS, BRANDS_DOMAINS, DEPLOY_PLATFORMS, PHISHING_DOMAINS
from .constants import IP_REGEX
from .constants import DYNAMIC_DNS_PROVIDERS, SPECIAL_CHARACTERES, NUMBER_TO_LETTER

from typing import Tuple, List

from datetime import datetime
from dateutil import parser

from OpenSSL import SSL
import whois,requests, socket
import json, re, Levenshtein

def is_ip_address(url: str):
    return bool(re.fullmatch(IP_REGEX, url))

def treat_url(url: str):
    """Remove o protocolo e o caminho da URL, retornando apenas o domínio"""
    url_treated = url.strip()
    url_treated = url_treated.replace("http://", "").replace("https://", "")
    if "/" in url_treated:
        url_treated = url_treated.split("/")[0]
    return url_treated

def check_dynamic_dns(domain: str):
    """Verifica se um domínio pertence a um serviço de DNS dinâmico"""
    for provider in DYNAMIC_DNS_PROVIDERS:
        if domain.endswith(provider):
            return True
    return False

def analyze_url_domains(url: str):
    """Analisa o domínio da URL e retorna os subdomínios, o nome do domínio e os TLDs"""
    url_domains = url.split(".")
    tlds = []
    for i in range(len(url_domains)):
        tld = url_domains[-1]
        if tld in TLDS:
            tlds.append(tld)
            url_domains = url_domains[:-1]
        else:
            break
    tlds:List[str] = tlds[::-1]
    if len(url_domains) > 0:
        name = url_domains[-1]
        subdomains = url_domains[:-1]
        return subdomains, name, tlds
    else:
        return [], "", tlds


def numbers_in_domain(domain: str):
    count = 0
    for i, char in enumerate(domain):
        if char in NUMBER_TO_LETTER.keys():
            count += 1
    return count

def special_characteres_in_domain(domain: str):
    count = 0
    for char in domain:
        if char in SPECIAL_CHARACTERES:
            count += 1
    return count

whois.logging.getLogger("whois").setLevel(whois.logging.CRITICAL)
def whois_consult(url: str):    

    try:
        winfo = whois.whois(url)
    except:
        winfo = None

    if winfo is not None:
        if winfo and winfo.domain_name is not None:
            domain_name = winfo.domain_name
            if isinstance(domain_name, list):
                domain_name = domain_name[0]

            if winfo.creation_date is not None:
                creation_date = winfo.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(creation_date, str):
                    creation_date = parser.parse(creation_date).replace(tzinfo=None)
                return domain_name.lower(), (datetime.now() - creation_date).days
    return None, None

def reduce_whois_consult(full_domain:str, main_domain:str):
    if full_domain == main_domain:
        whois_domain, whois_age =  whois_consult(main_domain)
        return whois_domain, whois_age, main_domain
    main_parts = main_domain.split('.')
    parts = full_domain.split('.')
    
    while len(parts) >= len(main_parts):
        current_domain = ".".join(parts)
        whois_domain, whois_age =  whois_consult(current_domain)
        if whois_domain is not None:
            return whois_domain, whois_age, current_domain
        parts.pop(0) 
    
    return None, None, None

def brand_levenshtein_distance(domain: str):
    match_name = None
    match_distance = float("inf")
    match_part = None
    in_matchs = set()
    
    subdomains, domain_name, tlds = analyze_url_domains(domain)
    fullname = ".".join(subdomains + [domain_name])
    subdomain_parts = "-".join(subdomains).split("-")
    all_domain_parts = [part for part in (subdomain_parts + [domain_name, fullname]) if len(part) > 3]

    for brand in BRANDS:
        
        for domain_part in all_domain_parts:
            dist = Levenshtein.distance(brand, domain_part)
        
            if dist < match_distance:
                match_name = brand
                match_distance = dist
                match_part = domain_part
        
            if domain_part.startswith(brand) or domain_part.endswith(brand):
                in_matchs.add(brand)
    
    return match_name, match_distance, match_part, list(in_matchs)

def domain_levenshtein_distance(domain: str):
    match_name = None
    match_distance = float("inf")
    
    for brand_domain in BRANDS_DOMAINS:
        dist = Levenshtein.distance(brand_domain, domain)
    
        if dist < match_distance:
            match_name = brand_domain
            match_distance = dist
    
    return match_name, match_distance


def check_deploy_platform(domain: str):
    for host in DEPLOY_PLATFORMS:
        if domain.endswith(host):
            return host
    return None

def consult_google_safe_browsing(domain: str):
    if GOOGLE_API_KEY is None:
        return None
    try:
        response = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}",
            headers = {"Content-Type": "application/json"},
            data = json.dumps({
                "client": {"clientId": "rafaeldbo-phishing-detector", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": domain}]
                }
            }),
            timeout=5,
        )
        if response.status_code == 200:
            data = response.json()
            if len(data.keys()) > 0:
                matches = data.get("matches")
                if matches is not None:
                    return [match.get("threatType") for match in matches]
        else:
            print(f"Error: Google Safe Browsing API request failed: {response.status_code}: {response.reason}")
    except Exception as e:
        print(f"Error: Google Safe Browsing API request failed:")
    return None

def consult_SSL_info(domain: str):
    try:
        sock = socket.create_connection((domain, 443), timeout=5)
        sock.setblocking(True)

        ssl_sock = SSL.Connection(SSL.Context(SSL.TLSv1_2_METHOD), sock)
        ssl_sock.set_tlsext_host_name(domain.encode())
        ssl_sock.set_connect_state()

        # tentando conectar no site (5 tentativas)
        i = 0
        while i < 5:
            try:
                ssl_sock.do_handshake()
                break
            except SSL.WantReadError:
                i += 1
                continue

        cert = ssl_sock.get_peer_certificate()

        ssl_sock.close()
        sock.close()

        if cert:
            data = {
                "issuer": cert.get_issuer().CN,
                "subject": cert.get_subject().CN,
                "expiration_date": datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ"),
            }
            if all([(value is not None) for value in data.values()]):
                data["subject"] = data["subject"].lower().replace("*.", "")
                return data

    except Exception as e:
        print(f"Error retrieving SSL info for {domain}")
        return None
    print(f"Could not obtain SSL information for the domain {domain}")
    return None

def detect_redirects(domain:str):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"
    }
    url = domain
    if not domain.startswith("http://") and not domain.startswith("https://"):
        url = "https://" + domain
        
    try:
        response = requests.get(url, headers=headers, allow_redirects=True, timeout=5)
        return [(resp.status_code, resp.url) for resp in response.history] + [(response.status_code, response.url)]
    
    except Exception as e:
        print(f"Error when detecting redirects from domain {domain}")
        return None
    
def known_phishing_domain(domain: str):
    return domain in PHISHING_DOMAINS