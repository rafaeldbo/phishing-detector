from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .tools import *
from .utils import parse_days

from pydantic import BaseModel

app = FastAPI()
# Allow CORS for all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URL(BaseModel):
    url: str

@app.post("/phishing")
async def detect_phishing(body: URL) -> dict:
    data = {}
    url = body.url
    print(f"Analisando URL: {url}")
    full_domain = treat_url(url)
    if is_ip_address(full_domain):
        raise HTTPException(status_code=400, detail="Apenas Domínios são aceitos")
    
    subdomains, name, tlds = analyze_url_domains(full_domain)
    main_domain = ".".join([name]+tlds)
    
    if known_phishing_domain(full_domain):
        return {
            "domain": full_domain,
            "phishing": "Pishing Detectado",
            "score": 5,
            "analysis": {
                "known_phishing_domain": ("Suspeita Alta", f"O domínio '{full_domain}' é conhecido por estar associado a phishing")
            }
        }
        
    deploy_platform = check_deploy_platform(main_domain)
    if deploy_platform is None and known_brand_domain(full_domain):
        return {
            "domain": full_domain,
            "phishing": "Domínio Parece Seguro",
            "score": 0,
            "analysis": {
                "known_brand_domain": ("Informação", f"O domínio '{full_domain}' é conhecido por estar associado a uma marca legítima")
            }
        }
    
    redirects = detect_redirects(full_domain)
    
    whois_domain, domain_age, used_domain = reduce_whois_consult(full_domain, main_domain)
    
    ssl_info = consult_SSL_info(full_domain)
    
    safe_browsing_matchs = consult_google_safe_browsing(full_domain)
    
    if redirects is None and whois_domain is None and ssl_info is None and safe_browsing_matchs is None:
        raise HTTPException(status_code=502, detail="Não foi possível obter informações do domínio, é provável que o domínio não exista")
    
    levenshtein_domain, levenshtein_domain_distance = domain_levenshtein_distance(full_domain)
    
    levenshtein_brand, levenshtein_brand_distance, domain_match_part, finded_brand_matchs = brand_levenshtein_distance(full_domain)
    
    number_chars = numbers_in_domain(full_domain)
    spacial_chars = special_characteres_in_domain(full_domain)
    
    if spacial_chars > 0:
        data["characters_in_domain"] = ("Suspeita Moderada", f"Domínio contém {spacial_chars} caracteres especiais")
        
    if number_chars >= 3:
        data["numbers_in_domain"] = ("Suspeita Baixa", f"Domínio contém {number_chars} números que podem estar substituindo letras")
        
    if len(subdomains) > 2:
        data["subdomains"] = ("Suspeita Moderada", f"Domínio contém muitos subdomínios ({len(subdomains)})")
    
    if deploy_platform:
        data["deploy_platform"] = ("Suspeita Baixa", f"Domínio hospedado na plataforma '{deploy_platform}'")
    else:
        deploy_platform = ""
        
    if redirects:
        for redirect in redirects:
            _, redirect_url = redirect
            if name not in treat_url(redirect_url):
                data["redirects"] = ("Suspeita Moderada", f"Redirecionamento suspeito detectado para '{redirect_url}'")
        
    if whois_domain:
        if whois_domain != deploy_platform:
            whois_suspicios = "Sem Suspeitas"
            if (domain_age <= 30): whois_suspicios = "Suspeita Alta"
            elif (domain_age <= 90): whois_suspicios = "Suspeita Moderada"
            elif (domain_age <= 365): whois_suspicios = "Baixa Suspeita"
            data["domain_age"] = (whois_suspicios, f"O domínio '{whois_domain}' tem {parse_days(domain_age)} de idade no registro WHOIS")
        else:
            data["domain_age"] = ("Informação", f"O registro WHOIS do domínio é o mesmo que a plataforma de hospedagem '{deploy_platform}'")
    else:
        data["domain_age"] = ("Suspeita Baixa", f"Não foi opter informações do domínio no registro WHOIS")
        
    levenshtein_domain_flag = False
    if levenshtein_domain != deploy_platform:
        if levenshtein_domain_distance == 0:
            levenshtein_domain_flag = True
        elif levenshtein_domain_distance > 0 and levenshtein_domain_distance <= 4:
            data["levenshtein_domain"] = ("Suspeita Alta", f"Proximidade com o domínio '{levenshtein_domain}'")
            levenshtein_domain_flag = True
            
                
    if not levenshtein_domain_flag:
        if levenshtein_brand not in deploy_platform:
            if levenshtein_brand_distance <= 2:
                data["levenshtein_brand"] = ("Suspeita Moderada", f"A parte do domínio '{domain_match_part}' é semelhante a marca '{levenshtein_brand}'")
                if levenshtein_brand in finded_brand_matchs:
                    finded_brand_matchs.remove(levenshtein_brand)
        finded_brand_matchs = [brand for brand in finded_brand_matchs if brand not in deploy_platform]
        if len(finded_brand_matchs) > 0:
            if len(finded_brand_matchs) == 1:
                data["brand_match"] = ("Suspeita Moderada", f"Domínio contém a marca '{finded_brand_matchs[0]}'")
            else:
                data["brand_match"] = ("Suspeita Moderada", f"Domínio contém as marcas {', '.join(finded_brand_matchs)}")
        
    if safe_browsing_matchs:
        if len(safe_browsing_matchs) == 1:
            data["google_safe_browsing"] = ("Suspeita Alta", f"Domínio está listado no Google Safe Browsing como '{safe_browsing_matchs[0]}'")
        else:
            data["google_safe_browsing"] = ("Suspeita Alta", f"Domínio está listado no Google Safe Browsing como {', '.join(safe_browsing_matchs)}")
    
    if ssl_info:
        if ssl_info["subject"] != deploy_platform:
            ssl_subject, ssl_expiration = ssl_info["subject"],ssl_info["expiration_date"]
            if (full_domain not in ssl_subject) and (ssl_subject not in full_domain):
                data["ssl"] = ("Suspeita Alta", f"O certificado SSL do domínio '{ssl_subject}' não corresponde ao domínio analisado")
            elif ssl_expiration < datetime.now():
                data["ssl"] = ("Suspeita Alta", f"O certificado SSL do domínio '{ssl_subject}' expirou em {ssl_expiration.strftime('%d/%m/%Y')}")
        else:
            data["ssl"] = ("Informação", f"O certificado SSL do domínio é o mesmo que o da plataforma de hospedagem '{deploy_platform}'")
    else:
        data["ssl"] = ("Suspeita Baixa", "Não foi possível obter informações do certificado SSL do domínio")
        
    score = 0
    for suspicious, _ in data.values():
        if suspicious == "Suspeita Baixa":
            score += 1
        elif suspicious == "Suspeita Moderada":
            score += 2
        elif suspicious == "Suspeita Alta":
            score += 5
        
    verdict = "Domínio Parece Seguro"
    if score >= 5:
        verdict = "Pishing Detectado"
    elif score >= 3:
        verdict = "Suspeita de Phishing Moderada"
    elif score >= 15:
        verdict = "Suspeita de Phishing Baixa"
        
    return {
        "domain": full_domain,
        "phishing": verdict,
        "score": score,
        "analysis": data,
    }
