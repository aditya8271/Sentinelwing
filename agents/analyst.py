# analyst.py

class AnalystAgent:
    def __init__(self):
        # Critical keywords that immediately trigger high risk
        self.malicious_keywords = ["unauthorized", "critical", "denied", "failed", "attack"]
        self.risk_threshold = 70

    def analyze_log(self, log_data):
        """
        Evaluates a log entry and returns a risk report.
        log_data: dict containing 'event_type', 'description', 'timestamp'
        """
        score = 0
        description = log_data.get('description', '').lower()
        
        # 1. Keyword analysis (Simple Rule-based AI)
        for word in self.malicious_keywords:
            if word in description:
                score += 30
        
        # 2. Logic-based scoring (e.g., specific event types)
        if log_data.get('event_type') == "FileDeletion":
            score += 40
        elif log_data.get('event_type') == "LoginAttempt":
            score += 20

        # Determine severity
        severity = "LOW"
        if score >= self.risk_threshold:
            severity = "CRITICAL"
        elif score >= 40:
            severity = "MEDIUM"

        message = f"Detected {severity.lower()} risk event based on log analysis."
        return {
            "risk_score": score,
            "severity": severity,
            "trigger_popup": score >= self.risk_threshold,
            "original_log": log_data,
            "message": message
        }
