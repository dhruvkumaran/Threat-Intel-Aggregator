import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    CROWDSEC_API_KEY = os.getenv("CROWDSEC_API_KEY", "your_crowdsec_api_key")
    ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY", "your_alienvault_api_key")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "your_virustotal_api_key")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "your_abuseipdb_api_key")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") # Add this line
    DATABASE_PATH = "threat_intel.db"
    SECRET_KEY = os.getenv("SECRET_KEY", "your_flask_secret_key")
    URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/text/"
    OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
    LOG_FILE = "threat_intel.log"