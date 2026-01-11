class ResponderAgent:
    def respond(self, analysis):
        if analysis["severity"] == "HIGH":
            return "Threat blocked and access restricted"
        return "No action required"
