import google.generativeai as genai
from config import Config
from logger import setup_logging

logger = setup_logging(Config.LOG_FILE)

class GeminiClient:
    def __init__(self):
        if not Config.GEMINI_API_KEY:
            logger.error("GEMINI_API_KEY is not set in config.py or .env. Gemini analysis will be unavailable.")
            self.model = None
            return

        try:
            genai.configure(api_key=Config.GEMINI_API_KEY)
            self.model = self._find_suitable_model()
            if self.model:
                logger.info(f"Gemini API client initialized successfully with model: {self.model.name}.")
            else:
                logger.error("No suitable Gemini model found for content generation.")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini API client: {e}")
            self.model = None

    def _find_suitable_model(self):
        """Finds a generative model that supports 'generateContent'."""
        try:
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    # Prioritize models like gemini-pro or others suitable for text generation
                    if "gemini-pro" in m.name:
                        return genai.GenerativeModel(m.name)
                    # Fallback to the first available generative model if gemini-pro is not found
                    # return genai.GenerativeModel(m.name) # Uncomment if you want to use the first found
            return None
        except Exception as e:
            logger.error(f"Error listing Gemini models: {e}")
            return None

    def analyze_threat_intel(self, indicator, ioc_type, raw_results):
        if not self.model:
            return {"error": "Gemini API client not initialized. Check API key and logs."}

        prompt = self._create_prompt(indicator, ioc_type, raw_results)
        
        try:
            response = self.model.generate_content(prompt)
            # Access content directly if the response structure changes
            if hasattr(response, 'text'):
                return self._parse_gemini_response(response.text)
            else:
                logger.error(f"Gemini response object has no 'text' attribute: {response}")
                return {"error": "Failed to get text response from Gemini API.", "raw_response": str(response)}
        except Exception as e:
            logger.error(f"Error calling Gemini API for {indicator}: {e}")
            return {"error": f"Failed to get response from Gemini API: {e}"}

    def _create_prompt(self, indicator, ioc_type, raw_results):
        # Your existing _create_prompt implementation
        prompt = f"Analyze the following threat intelligence data for indicator '{indicator}' of type '{ioc_type}':\n\n"
        
        for source, data in raw_results.items():
            prompt += f"--- {source.upper()} ---\n"
            if isinstance(data, dict):
                for key, value in data.items():
                    if value: # Only add if value is not empty or None
                        if isinstance(value, list):
                            prompt += f"{key.replace('_', ' ').title()}: {', '.join(map(str, value))}\n"
                        elif isinstance(value, dict):
                            prompt += f"{key.replace('_', ' ').title()}:\n"
                            for sub_key, sub_value in value.items():
                                prompt += f"  - {sub_key.replace('_', ' ').title()}: {sub_value}\n"
                        else:
                            prompt += f"{key.replace('_', ' ').title()}: {value}\n"
            elif data: # For non-dict data that might just be a simple string/list
                prompt += f"Raw Data: {data}\n"
            else:
                prompt += "No data found.\n"
            prompt += "\n"

        prompt += (
            "Based on the combined information, provide a comprehensive analysis. "
            "Evaluate the threat level (Low, Medium, High, Critical), summarize the findings, "
            "identify any specific IOCs mentioned (if different from the input), and suggest actionable recommendations.\n"
            "Specifically, identify if the indicator itself, or any related indicators found in the results, "
            "are explicitly marked as malicious, suspicious, or have a high confidence score of being malicious.\n"
            "Also, list any specific IOCs found in the results (e.g., URLs, domains, IPs, hashes) that are clearly malicious.\n"
            "Provide concrete recommendations based on your analysis.\n"
            "If no clear malicious indicators are found, state that and provide general cybersecurity recommendations."
        )       
        prompt += "\nPlease format your response as a JSON object with keys: 'total_score' (integer), 'severity' (string: Low, Medium, High, Critical), 'summary' (string detailed explanation), 'iocs_found' (list of strings, e.g., ['malicious.com', '1.2.3.4']), 'recommendations' (list of strings)."
        return prompt

    def _parse_gemini_response(self, text_response):
        try:
            if "```json" in text_response:
                json_str = text_response.split("```json")[1].split("```")[0].strip()
            else:
                json_str = text_response.strip()
            
            parsed_data = json.loads(json_str)
            if all(k in parsed_data for k in ['total_score', 'severity', 'summary']):
                # Ensure 'iocs_found' and 'recommendations' are lists, default to empty list if missing
                parsed_data['iocs_found'] = parsed_data.get('iocs_found', [])
                parsed_data['recommendations'] = parsed_data.get('recommendations', [])
                return parsed_data
            else:
                logger.warning(f"Gemini response JSON missing expected keys: {parsed_data}")
                return {"error": "Gemini response JSON missing expected keys.", "raw_response": text_response}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Gemini JSON response: {e}\nRaw response: {text_response}")
            return {"error": "Failed to parse Gemini response as JSON.", "raw_response": text_response}
        except Exception as e:
            logger.error(f"Error in parsing Gemini response: {e}\nRaw response: {text_response}")
            return {"error": f"Error parsing Gemini response: {e}", "raw_response": text_response}