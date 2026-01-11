class HealerAgent:
    def heal(self, analysis):
        if analysis["severity"] == "HIGH":
            return "System restored to secure state"
        return "System healthy"
