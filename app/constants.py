
import os
from dotenv import load_dotenv

load_dotenv(override=True)
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

PATH = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(PATH, "src", "ALL-phishing-domains.txt"), "r") as file:
    PHISHING_DOMAINS = [line.strip().lower() for line in file]
    
with open(os.path.join(PATH, "src", "TLDs.txt"), "r") as file:
    TLDS = [line.strip().lower() for line in file]
    
with open(os.path.join(PATH, "src", "brands.txt"), "r") as file:
    BRANDS = [line.strip().lower() for line in file]
    
with open(os.path.join(PATH, "src", "brands_domains.txt"), "r") as file:
    BRANDS_DOMAINS = [line.strip().lower() for line in file]
 
IP_REGEX = r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

DYNAMIC_DNS_PROVIDERS = [
    "no-ip.com", "dyn.com", "dyndns.org", "duckdns.org", "afraid.org",
    "changeip.com", "ddns.net", "zapto.org", "myftp.org", "duckdns.org"
]
DEPLOY_PLATFORMS = [
    "github.io", "vercel.app", "amazonaws.com", "weebly.com",
    "repl.co", "glitch.me", "netlify.app", "onrender.com",
    "web.app", "fly.dev", "digitaloceanspaces.com",
    "azurewebsites.net", "appspot.com", "herokuapp.com",
    "weeblysite.com", "blogspot.com",
]
SPECIAL_CHARACTERES = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '=', '+', '{', '}', '[', ']', ':', ';', '"', "'", '<', '>', ',', '?', '|']
NUMBER_TO_LETTER = {'4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't'}
