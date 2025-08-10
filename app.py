import sqlite3
import requests
from flask import Flask, render_template, request, jsonify
from config import Config
import json
from urllib.parse import urlparse, quote
from ioc_normalizer import normalize_ioc
from logger import setup_logging
from alerter import Alerter
import datetime
from threat_analyzer import ThreatAnalyzer

app = Flask(__name__)
app.config.from_object(Config)
logger = setup_logging(Config.LOG_FILE)
alerter = Alerter(logger)

# Database Manager Class (rest of your app.py content before query_ioc)
class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT,
                    type TEXT,
                    urlhaus_result TEXT,
                    openphish_result TEXT,
                    crowdsec_result TEXT,
                    alienvault_result TEXT,
                    virustotal_result TEXT,
                    abuseipdb_result TEXT,
                    gemini_analysis_result TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            try:
                cursor.execute("ALTER TABLE queries ADD COLUMN gemini_analysis_result TEXT")
                conn.commit()
                logger.info("Added 'gemini_analysis_result' column to queries table.")
            except sqlite3.OperationalError as e:
                if "duplicate column name: gemini_analysis_result" in str(e):
                    logger.info("'gemini_analysis_result' column already exists.")
                else:
                    logger.error(f"Error altering table: {e}")
            conn.commit()

    def add_query(self, indicator, ioc_type, urlhaus_result, openphish_result, crowdsec_result, alienvault_result, virustotal_result, abuseipdb_result, gemini_analysis_result):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO queries (indicator, type, urlhaus_result, openphish_result, crowdsec_result, alienvault_result, virustotal_result, abuseipdb_result, gemini_analysis_result)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                indicator, ioc_type,
                json.dumps(urlhaus_result),
                json.dumps(openphish_result),
                json.dumps(crowdsec_result),
                json.dumps(alienvault_result),
                json.dumps(virustotal_result),
                json.dumps(abuseipdb_result),
                json.dumps(gemini_analysis_result)
            ))
            conn.commit()
            return cursor.lastrowid

    def get_all_queries(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM queries ORDER BY timestamp DESC")
            queries = []
            for row in cursor.fetchall():
                q_data = dict(row)
                for key in ['urlhaus_result', 'openphish_result', 'crowdsec_result', 'alienvault_result', 'virustotal_result', 'abuseipdb_result', 'gemini_analysis_result']:
                    try:
                        q_data[key] = json.loads(q_data[key]) if q_data[key] else {}
                    except json.JSONDecodeError:
                        logger.error(f"Failed to decode JSON for {key} in query ID {q_data['id']}: {q_data[key]}")
                        q_data[key] = {"error": "Invalid JSON data"}
                queries.append(q_data)
            return queries

db_manager = DatabaseManager(Config.DATABASE_PATH)

# Existing client classes (URLhausClient, OpenPhishClient, CrowdSecClient, AlienVaultClient, VirusTotalClient, AbuseIPDBClient)
# Ensure these are present and correctly defined in your app.py.
class URLhausClient:
    def __init__(self):
        self.feed_url = Config.URLHAUS_FEED_URL

    def query_ip(self, ip):
        try:
            response = requests.get(self.feed_url, timeout=10)
            response.raise_for_status()
            urls = response.text.splitlines()
            matching_urls = [url for url in urls if ip in url]
            return {"matches": matching_urls}
        except requests.exceptions.RequestException as e:
            logger.error(f"URLhaus query failed: {e}")
            return {"error": str(e), "matches": []}

class OpenPhishClient:
    def __init__(self):
        self.feed_url = Config.OPENPHISH_FEED_URL

    def query_domain(self, domain):
        try:
            response = requests.get(self.feed_url, timeout=10)
            response.raise_for_status()
            domains = response.text.splitlines()
            matching_domains = [d for d in domains if domain in d]
            return {"matches": matching_domains}
        except requests.exceptions.RequestException as e:
            logger.error(f"OpenPhish query failed: {e}")
            return {"error": str(e), "matches": []}

class CrowdSecClient:
    def __init__(self):
        self.api_key = Config.CROWDSEC_API_KEY
        self.api_url = "https://api.crowdsec.net/v2/decisions" # Example API URL, adjust if yours is different

    def query_ip(self, ip):
        if not self.api_key or self.api_key == "your_crowdsec_api_key":
            return {"error": "CrowdSec API key not configured.", "score": 0, "behaviors": []}
        headers = {"X-Api-Key": self.api_key, "User-Agent": "ThreatIntelDashboard/1.0"}
        params = {"ip": ip}
        try:
            response = requests.get(self.api_url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            return {
                "score": len(data) if data else 0,
                "behaviors": [{"label": d.get("scenario", "Unknown")} for d in data] if data else []
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"CrowdSec query failed for {ip}: {e}")
            return {"error": str(e), "score": 0, "behaviors": []}
        except json.JSONDecodeError:
            logger.error(f"CrowdSec response for {ip} not JSON: {response.text}")
            return {"error": "Invalid JSON response from CrowdSec", "score": 0, "behaviors": []}

class AlienVaultClient:
    def __init__(self):
        self.api_key = Config.ALIENVAULT_API_KEY
        self.base_url = "https://otx.alienvault.com/api/v1/indicators"

    def query_indicator(self, indicator, ioc_type):
        if not self.api_key or self.api_key == "your_alienvault_api_key":
            return {"error": "AlienVault API key not configured.", "pulse_count": 0, "reputation": 0}
        headers = {"X-OTX-API-KEY": self.api_key}
        if ioc_type == "IPv4":
            url = f"{self.base_url}/IPv4/{indicator}/general"
        elif ioc_type == "domain":
            url = f"{self.base_url}/domain/{indicator}/general"
        else:
            return {"error": "Unsupported IOC type for AlienVault", "pulse_count": 0, "reputation": 0}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return {
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "reputation": data.get("reputation", 0)
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"AlienVault OTX query failed for {indicator}: {e}")
            return {"error": str(e), "pulse_count": 0, "reputation": 0}
        except json.JSONDecodeError:
            logger.error(f"AlienVault response for {indicator} not JSON: {response.text}")
            return {"error": "Invalid JSON response from AlienVault", "pulse_count": 0, "reputation": 0}

class VirusTotalClient:
    def __init__(self):
        self.api_key = Config.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    def _get_analysis_results(self, data):
        malicious = 0
        suspicious = 0
        harmless = 0
        if data and "data" in data and "attributes" in data["data"] and "last_analysis_stats" in data["data"]["attributes"]:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
        return {"malicious": malicious, "suspicious": suspicious, "harmless": harmless}

    def query_ip(self, ip):
        if not self.api_key or self.api_key == "your_virustotal_api_key":
            return {"error": "VirusTotal API key not configured.", "malicious": 0, "suspicious": 0, "harmless": 0}
        url = f"{self.base_url}/ip_addresses/{ip}"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return self._get_analysis_results(response.json())
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal IP query failed for {ip}: {e}")
            return {"error": str(e), "malicious": 0, "suspicious": 0, "harmless": 0}
        except json.JSONDecodeError:
            logger.error(f"VirusTotal IP response for {ip} not JSON: {response.text}")
            return {"error": "Invalid JSON response from VirusTotal IP", "malicious": 0, "suspicious": 0, "harmless": 0}

    def query_domain(self, domain):
        if not self.api_key or self.api_key == "your_virustotal_api_key":
            return {"error": "VirusTotal API key not configured.", "malicious": 0, "suspicious": 0, "harmless": 0}
        url = f"{self.base_url}/domains/{domain}"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return self._get_analysis_results(response.json())
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal Domain query failed for {domain}: {e}")
            return {"error": str(e), "malicious": 0, "suspicious": 0, "harmless": 0}
        except json.JSONDecodeError:
            logger.error(f"VirusTotal Domain response for {domain} not JSON: {response.text}")
            return {"error": "Invalid JSON response from VirusTotal Domain", "malicious": 0, "suspicious": 0, "harmless": 0}

    def query_hash(self, file_hash):
        if not self.api_key or self.api_key == "your_virustotal_api_key":
            return {"error": "VirusTotal API key not configured.", "malicious": 0, "suspicious": 0, "harmless": 0}
        url = f"{self.base_url}/files/{file_hash}"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return self._get_analysis_results(response.json())
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal Hash query failed for {file_hash}: {e}")
            return {"error": str(e), "malicious": 0, "suspicious": 0, "harmless": 0}
        except json.JSONDecodeError:
            logger.error(f"VirusTotal Hash response for {file_hash} not JSON: {response.text}")
            return {"error": "Invalid JSON response from VirusTotal Hash", "malicious": 0, "suspicious": 0, "harmless": 0}

class AbuseIPDBClient:
    def __init__(self):
        self.api_key = Config.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }

    def query_ip(self, ip):
        if not self.api_key or self.api_key == "your_abuseipdb_api_key":
            return {"error": "AbuseIPDB API key not configured.", "confidence_score": 0, "reports": 0}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        try:
            response = requests.get(f"{self.base_url}/check", headers=self.headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data and "data" in data:
                return {
                    "confidence_score": data["data"].get("abuseConfidenceScore", 0),
                    "reports": data["data"].get("totalReports", 0)
                }
            return {"confidence_score": 0, "reports": 0, "error": "No data in AbuseIPDB response"}
        except requests.exceptions.RequestException as e:
            logger.error(f"AbuseIPDB query failed for {ip}: {e}")
            return {"error": str(e), "confidence_score": 0, "reports": 0}
        except json.JSONDecodeError:
            logger.error(f"AbuseIPDB response for {ip} not JSON: {response.text}")
            return {"error": "Invalid JSON response from AbuseIPDB", "confidence_score": 0, "reports": 0}


@app.route("/")
def index():
    queries = db_manager.get_all_queries()
    # Pass all query data directly. The Jinja2 template will handle the first query for Gemini.
    return render_template("index.html", queries=queries)

@app.route("/query", methods=["POST"])
def query_ioc():
    indicator = request.form.get("indicator")
    ioc_type = request.form.get("ioc_type")

    if not indicator or not ioc_type:
        return jsonify({"error": "Indicator and type are required"}), 400

    # Capture the tuple from normalize_ioc
    normalized_result = normalize_ioc(indicator, ioc_type)
    
    if not normalized_result:
        alerter.console_alert(f"Invalid IOC format: {indicator} of type {ioc_type}")
        return jsonify({"error": "Invalid IOC format."}), 400

    # Extract the actual indicator string and its type from the tuple
    normalized_indicator_string, normalized_type = normalized_result

    logger.info(f"Querying IOC: {normalized_indicator_string} ({normalized_type})")

    # Initialize results with default structures to ensure consistency
    urlhaus_result = {}
    openphish_result = {}
    crowdsec_result = {}
    alienvault_result = {}
    virustotal_result = {}
    abuseipdb_result = {}

    # Instantiate clients inside the request context
    urlhaus_client = URLhausClient()
    openphish_client = OpenPhishClient()
    crowdsec_client = CrowdSecClient()
    alienvault_client = AlienVaultClient()
    virustotal_client = VirusTotalClient()
    abuseipdb_client = AbuseIPDBClient()

    try:
        # Perform API queries based on IOC type, passing the string
        if normalized_type == "IP":
            urlhaus_result = urlhaus_client.query_ip(normalized_indicator_string)
            crowdsec_result = crowdsec_client.query_ip(normalized_indicator_string)
            alienvault_result = alienvault_client.query_indicator(normalized_indicator_string, "IPv4") # Assume IPv4 for IP type
            virustotal_result = virustotal_client.query_ip(normalized_indicator_string)
            abuseipdb_result = abuseipdb_client.query_ip(normalized_indicator_string)
        elif normalized_type == "Domain":
            openphish_result = openphish_client.query_domain(normalized_indicator_string)
            alienvault_result = alienvault_client.query_indicator(normalized_indicator_string, "domain")
            virustotal_result = virustotal_client.query_domain(normalized_indicator_string)
        elif normalized_type == "Hash":
            virustotal_result = virustotal_client.query_hash(normalized_indicator_string)
        else:
            return jsonify({"error": "Unsupported IOC type provided."}), 400

        raw_results = {
            "urlhaus": urlhaus_result,
            "openphish": openphish_result,
            "crowdsec": crowdsec_result,
            "alienvault": alienvault_result,
            "virustotal": virustotal_result,
            "abuseipdb": abuseipdb_result
        }

        # Perform integrated threat analysis (including Gemini or fallback)
        gemini_analysis_result = ThreatAnalyzer.analyze(normalized_indicator_string, normalized_type, raw_results)
        
        # Store all results in the database, including the Gemini analysis
        db_manager.add_query(
            normalized_indicator_string, normalized_type, # Store the string, not the tuple
            urlhaus_result, openphish_result, crowdsec_result,
            alienvault_result, virustotal_result, abuseipdb_result,
            gemini_analysis_result
        )

        return jsonify({"status": "success", "message": "IOC queried and results saved."})

    except Exception as e:
        logger.exception(f"An unexpected error occurred during IOC query for {indicator}: {e}")
        return jsonify({"error": f"An internal server error occurred: {str(e)}"}), 500


@app.route("/search")
def search():
    query = request.args.get("q", "").lower()
    queries = db_manager.get_all_queries()
    
    filtered_queries = []
    for q in queries:
        # Safely access gemini_analysis_result and its properties
        gemini_summary = q.get('gemini_analysis_result', {}).get('summary', '').lower()
        gemini_iocs = [item.lower() for item in q.get('gemini_analysis_result', {}).get('iocs_found', [])]
        gemini_recommendations = [item.lower() for item in q.get('gemini_analysis_result', {}).get('recommendations', [])]

        if (q['indicator'] and query in q['indicator'].lower()) or \
           (q['type'] and query in q['type'].lower()) or \
           query in gemini_summary or \
           any(query in ioc for ioc in gemini_iocs) or \
           any(query in rec for rec in gemini_recommendations):
            filtered_queries.append(q)
    
    return jsonify(filtered_queries)


if __name__ == "__main__":
    db_manager.init_db() # Ensure DB is initialized on app start
    app.run(debug=True)