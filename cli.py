from textual.app import App
from textual.widgets import DataTable, Header, Footer, Input, Button
from textual.containers import Container
from textual.reactive import reactive
import json
import csv
from app import DatabaseManager # CHANGED: Import the DatabaseManager class
from config import Config # Import Config to get DATABASE_PATH

db_manager = DatabaseManager(Config.DATABASE_PATH) # ADDED: Instantiate db_manager here with path

class ThreatIntelCLI(App):
    CSS = """
    DataTable {
        height: 80%;
    }
    Input {
        margin: 1;
    }
    Button {
        margin: 1;
    }
    """
    
    filter_text = reactive("")

    def compose(self):
        yield Header()
        yield Input(placeholder="Filter IOCs...", id="filter")
        yield Button("Export CSV", id="export_csv")
        yield Button("Export JSON", id="export_json")
        yield DataTable()
        yield Footer()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.add_columns("ID", "Indicator", "Type", "VirusTotal", "AbuseIPDB", "Gemini Analysis", "Timestamp") # Added Gemini Analysis column
        self.load_data()

    def load_data(self):
        table = self.query_one(DataTable)
        table.clear()
        queries = db_manager.get_all_queries()
        for q in queries:
            # Safely access indicator and type before converting to lower
            indicator_lower = q[1].lower() if q[1] else ''
            type_lower = q[2].lower() if q[2] else ''

            if self.filter_text and self.filter_text.lower() not in (indicator_lower or type_lower):
                # Also filter by Gemini summary, if available
                gemini_result = json.loads(q[9]) if q[9] else {} # Assuming q[9] is gemini_analysis_result
                gemini_summary = gemini_result.get('summary', '').lower()
                if self.filter_text.lower() not in gemini_summary:
                    continue
            
            vt_result = json.loads(q[7]) if q[7] else {}
            abuse_result = json.loads(q[8]) if q[8] else {}
            gemini_result_for_display = json.loads(q[9]) if q[9] else {} # Get Gemini result for display

            gemini_summary_display = gemini_result_for_display.get("summary", "No Gemini analysis")
            if gemini_result_for_display.get("error"):
                gemini_summary_display = f"Error: {gemini_result_for_display['error']}"


            table.add_row(
                q[0],
                q[1],
                q[2],
                f"Malicious: {vt_result.get('malicious', 0)}" if not vt_result.get("error") else vt_result.get("error", "No data"),
                f"Score: {abuse_result.get('confidence_score', 0)}" if not abuse_result.get("error") else abuse_result.get("error", "No data"),
                gemini_summary_display, # Display Gemini summary
                q[9]
            )

    def on_input_changed(self, event: Input.Changed) -> None:
        self.filter_text = event.value
        self.load_data()

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "export_csv":
            self.export_csv()
            self.notify("Exported to threat_intel.csv")
        elif event.button.id == "export_json":
            self.export_json()
            self.notify("Exported to threat_intel.json")

    def export_csv(self):
        queries = db_manager.get_all_queries()
        with open("threat_intel.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Indicator", "Type", "URLhaus", "OpenPhish", "CrowdSec", "AlienVault", "VirusTotal", "AbuseIPDB", "Gemini Analysis", "Timestamp"])
            for q in queries:
                urlhaus_result = json.loads(q[3]) if q[3] else {}
                openphish_result = json.loads(q[4]) if q[4] else {}
                crowdsec_result = json.loads(q[5]) if q[5] else {}
                alienvault_result = json.loads(q[6]) if q[6] else {}
                vt_result = json.loads(q[7]) if q[7] else {}
                abuse_result = json.loads(q[8]) if q[8] else {}
                gemini_analysis_result = json.loads(q[9]) if q[9] else {}

                writer.writerow([
                    q[0],
                    q[1],
                    q[2],
                    f"{len(urlhaus_result.get('matches', []))} match(es)" if not urlhaus_result.get("error") else urlhaus_result.get("error", "No data"),
                    f"{len(openphish_result.get('matches', []))} match(es)" if not openphish_result.get("error") else openphish_result.get("error", "No data"),
                    f"Score: {crowdsec_result.get('score', 0)}" if not crowdsec_result.get("error") else crowdsec_result.get("error", "No data"),
                    f"Pulse Count: {alienvault_result.get('pulse_count', 0)}, Rep: {alienvault_result.get('reputation', 0)}" if not alienvault_result.get("error") else alienvault_result.get("error", "No data"),
                    f"Malicious: {vt_result.get('malicious', 0)}, Susp: {vt_result.get('suspicious', 0)}, Harm: {vt_result.get('harmless', 0)}" if not vt_result.get("error") else vt_result.get("error", "No data"),
                    f"Score: {abuse_result.get('confidence_score', 0)}" if not abuse_result.get("error") else abuse_result.get("error", "No data"),
                    gemini_analysis_result.get('summary', 'No summary') if not gemini_analysis_result.get("error") else gemini_analysis_result.get("error", "No data"),
                    q[9]
                ])

    def export_json(self):
        queries = db_manager.get_all_queries()
        data = []
        for q_tuple in queries:
            # Reconstruct dictionary from tuple based on table schema for export
            q_dict = {
                "id": q_tuple[0],
                "indicator": q_tuple[1],
                "type": q_tuple[2],
                "urlhaus_result": json.loads(q_tuple[3]) if q_tuple[3] else {},
                "openphish_result": json.loads(q_tuple[4]) if q_tuple[4] else {},
                "crowdsec_result": json.loads(q_tuple[5]) if q_tuple[5] else {},
                "alienvault_result": json.loads(q_tuple[6]) if q_tuple[6] else {},
                "virustotal_result": json.loads(q_tuple[7]) if q_tuple[7] else {},
                "abuseipdb_result": json.loads(q_tuple[8]) if q_tuple[8] else {},
                "gemini_analysis_result": json.loads(q_tuple[9]) if q_tuple[9] else {}, # Include Gemini
                "timestamp": q_tuple[10] # Adjust index for timestamp
            }
            data.append(q_dict)

        with open("threat_intel.json", "w") as f:
            json.dump(data, f, indent=4)


if __name__ == "__main__":
    app = ThreatIntelCLI()
    app.run()