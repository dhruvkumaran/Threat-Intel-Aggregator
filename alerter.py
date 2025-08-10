from config import Config

class Alerter:
    def __init__(self, logger):
        self.logger = logger

    def console_alert(self, message):
        """Print alert to console."""
        self.logger.warning(f"ALERT: {message}")