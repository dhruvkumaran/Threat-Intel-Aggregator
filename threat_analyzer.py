import json
from gemini_client import GeminiClient # Import the new Gemini client
from logger import setup_logging
from config import Config

logger = setup_logging(Config.LOG_FILE)

class ThreatAnalyzer:
    gemini_client = GeminiClient() # Initialize Gemini client once

    @staticmethod
    def analyze(indicator, ioc_type, raw_results):
        # Attempt Gemini analysis first
        if ThreatAnalyzer.gemini_client.model: # Check if Gemini client was initialized successfully
            logger.info(f"Attempting Gemini analysis for {indicator}...")
            gemini_analysis = ThreatAnalyzer.gemini_client.analyze_threat_intel(indicator, ioc_type, raw_results)
            
            if not gemini_analysis.get("error"):
                logger.info(f"Gemini analysis successful for {indicator}.")
                # Add indicator and type to the Gemini response for consistency in UI display
                # Note: These might already be added in _parse_gemini_response, but ensuring here.
                gemini_analysis["indicator"] = indicator
                gemini_analysis["type"] = ioc_type
                return gemini_analysis
            else:
                logger.warning(f"Gemini analysis failed or returned error for {indicator}: {gemini_analysis.get('error')}. Falling back to rule-based analysis.")
                # Store the error from Gemini if it failed, so it can be displayed
                return {"error": gemini_analysis.get("error", "Gemini analysis failed"), "indicator": indicator, "type": ioc_type}


        # Fallback to existing rule-based analysis if Gemini is not available or fails
        logger.info(f"Performing rule-based analysis for {indicator}.")
        score = 0
        summary_parts = [] # Use summary_parts to build a comprehensive summary
        severity = "Low"
        iocs_found = []
        recommendations = []

        # Initialize results with default safe values
        urlhaus_matches = raw_results.get("urlhaus", {}).get("matches", [])
        openphish_matches = raw_results.get("openphish", {}).get("matches", [])
        crowdsec_score = raw_results.get("crowdsec", {}).get("score", 0)
        crowdsec_behaviors = raw_results.get("crowdsec", {}).get("behaviors", [])
        alienvault_pulse_count = raw_results.get("alienvault", {}).get("pulse_count", 0)
        alienvault_reputation = raw_results.get("alienvault", {}).get("reputation", 0)
        virustotal_malicious = raw_results.get("virustotal", {}).get("malicious", 0)
        abuseipdb_confidence_score = raw_results.get("abuseipdb", {}).get("confidence_score", 0)


        # Rule-based scoring logic (simplified example, expand as needed)
        if urlhaus_matches:
            score += 40
            summary_parts.append(f"URLhaus found {len(urlhaus_matches)} match(es), indicating known malicious URLs.")
            recommendations.append("Block associated URLs and IPs at network perimeter.")
            iocs_found.extend(urlhaus_matches)

        if openphish_matches:
            score += 40
            summary_parts.append(f"OpenPhish found {len(openphish_matches)} match(es), indicating phishing activity.")
            recommendations.append("Warn users about phishing attempts and implement email filters.")
            iocs_found.extend(openphish_matches)

        if crowdsec_score > 0:
            score += min(crowdsec_score * 5, 30) # Max 30 for CrowdSec score
            summary_parts.append(f"CrowdSec detected suspicious behavior (score: {crowdsec_score}).")
            for behavior in crowdsec_behaviors:
                summary_parts.append(f"- Behavior: {behavior.get('label', 'N/A')}")
            recommendations.append("Review logs for unusual activity from this IP and consider temporary blocking.")

        if virustotal_malicious > 0:
            score += min(virustotal_malicious * 10, 50) # Max 50 for VT malicious
            summary_parts.append(f"VirusTotal reported {virustotal_malicious} malicious detections.")
            recommendations.append("Isolate affected systems and perform malware analysis.")

        if abuseipdb_confidence_score > 0:
            score += min(abuseipdb_confidence_score / 2, 25) # Max 25 for AbuseIPDB
            summary_parts.append(f"AbuseIPDB reports a confidence score of {abuseipdb_confidence_score} for this IP.")
            recommendations.append("Implement IP blocking rules at firewall/proxy based on confidence score.")
        
        # AlienVault OTX (reputation and pulses)
        if alienvault_reputation < -50: # Example threshold for very bad reputation
            score += 30
            summary_parts.append(f"AlienVault OTX reports a very low reputation of {alienvault_reputation}, indicating known malicious activity.")
            recommendations.append("Strongly consider blocking this indicator based on its low reputation.")
        elif alienvault_reputation < 0:
            score += 15
            summary_parts.append(f"AlienVault OTX reports a negative reputation of {alienvault_reputation}.")
        
        if alienvault_pulse_count > 10: # Example threshold for many pulses
            score += 20
            summary_parts.append(f"AlienVault OTX shows a high number of {alienvault_pulse_count} related pulses, indicating widespread malicious context.")
            recommendations.append("Investigate connected indicators and apply proactive threat hunting.")
        elif alienvault_pulse_count > 0:
            score += 5
            summary_parts.append(f"AlienVault OTX shows {alienvault_pulse_count} related pulses.")

        # Determine overall severity based on the calculated score
        if score >= 90:
            severity = "Critical"
            summary_parts.insert(0, "This indicator is highly malicious and poses a severe threat.")
            recommendations.insert(0, "Immediate action is required to contain and eradicate this threat.")
        elif score >= 60:
            severity = "High"
            summary_parts.insert(0, "This indicator is likely malicious and requires immediate attention.")
            recommendations.insert(0, "Prioritize investigation and mitigation actions.")
        elif score >= 30:
            severity = "Medium"
            summary_parts.insert(0, "This indicator shows signs of suspicious activity and warrants investigation.")
            recommendations.insert(0, "Further analysis and monitoring are recommended.")
        else:
            severity = "Low"
            summary_parts.insert(0, "This indicator shows minimal or no signs of malicious activity.")
            recommendations.insert(0, "Monitor for future activity and maintain vigilance.")
        
        # Ensure unique IOCs and recommendations
        iocs_found = list(set(iocs_found))
        recommendations = list(set(recommendations))

        return {
            "indicator": indicator,
            "type": ioc_type,
            "total_score": min(100, int(score)), # Cap score at 100
            "severity": severity,
            "summary": " ".join(summary_parts) if summary_parts else "No significant malicious indicators found based on rule-based analysis.",
            "iocs_found": iocs_found,
            "recommendations": recommendations
        }