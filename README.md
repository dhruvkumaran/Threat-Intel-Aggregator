# Threat Intelligence Aggregator (TIA)

##  Overview
Threat Intelligence Aggregator is a centralized platform to collect, normalize, score, and visualize threat intelligence data from multiple trusted sources.  
It supports both **Web Dashboard (Flask + Plotly)** and **CLI Dashboard (Textual)** for versatile usage in cybersecurity workflows.

##  Features
- Integrates with multiple Threat Intelligence APIs:
  - AlienVault OTX
  - VirusTotal
  - AbuseIPDB
  - CrowdSec
  - OpenPhish
  - URLhaus
- IOC normalization & deduplication (IPs, domains, file hashes)
- AI-powered threat summarization & scoring using **Google Gemini**
- CLI interface with filtering, exporting (CSV/JSON), and mouse support
- Web dashboard with interactive graphs & real-time updates
- Local SQLite database for traceability & audit
- Export results to CSV and JSON formats
- Session-based login for secure access

##  Technology Stack
**Backend:** Python, Flask, Requests, SQLite, python-dotenv  
**Frontend:** HTML, Bootstrap, Tailwind CSS, Plotly, AJAX  
**CLI:** Textual (Python framework)  
**AI:** Google Generative AI (Gemini)  
**Other:** Logging, API integration, IOC normalization logic

##  Project Structure
├── app/ # Flask application files
├── cli/ # CLI dashboard implementation
├── database/ # SQLite database and schema
├── static/ # Frontend assets (CSS, JS, images)
├── templates/ # HTML templates for Flask
├── requirements.txt # Project dependencies
├── .env.example # Example environment variables
└── README.md # Project documentation

## API Keys Required
You need to generate API keys from:

AlienVault OTX
VirusTotal
AbuseIPDB
CrowdSec
OpenPhish
URLhaus
Google AI Studio


##  Installation
```bash
# Clone the repository
git clone https://github.com/dhruvkumaran/Threat-Intel-Aggregator.git
cd Threat-Intel-Aggregator

# Create & activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy .env.example to .env and add your keys
cp .env.example .env
```
## Usage
```bash
# Run web dashboard
flask run

# Run CLI dashboard
python cli/main.py
```
