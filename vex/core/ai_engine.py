import os
import json
from dotenv import load_dotenv


load_dotenv()


class AIEngine:
    """AI Engine for smart payload generation and analysis."""

    def __init__(self, model=None, api_key=None):
        self.model = model or os.getenv("AI_MODEL", "gpt-4o-mini")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.enabled = bool(self.api_key)

    def generate_sqli_payloads(self, context=None, count=10):
        """Generate smart SQLi payloads based on context."""
        if not self.enabled:
            return []
        try:
            import openai
            client = openai.Client(api_key=self.api_key)
            prompt = f"""Generate {count} safe, non-destructive SQL injection detection payloads.
Context: {context or 'Generic web application'}
Return ONLY a JSON array of payloads, no extra text.
Example: ["' OR '1'='1", "' AND SLEEP(5)--", "' UNION SELECT NULL--"]"""
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7
            )
            content = response.choices[0].message.content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            return json.loads(content)
        except Exception:
            return []

    def generate_xss_payloads(self, context=None, count=10):
        """Generate smart XSS payloads based on context."""
        if not self.enabled:
            return []
        try:
            import openai
            client = openai.Client(api_key=self.api_key)
            prompt = f"""Generate {count} safe XSS detection payloads with a unique marker (use "VEX_XSS_TEST").
Context: {context or 'Generic web application'}
Return ONLY a JSON array of payloads, no extra text.
Example: ['<script>alert("VEX_XSS_TEST")</script>', '<img src=x onerror=alert("VEX_XSS_TEST")>']"""
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7
            )
            content = response.choices[0].message.content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            return json.loads(content)
        except Exception:
            return []

    def analyze_response(self, response_text, vulnerability_type):
        """Analyze a response for potential vulnerability indicators."""
        if not self.enabled:
            return None
        try:
            import openai
            client = openai.Client(api_key=self.api_key)
            prompt = f"""Analyze this HTTP response body for {vulnerability_type} vulnerabilities.
Response:
{response_text[:2000]}

Return JSON with:
- "vulnerable": true/false
- "confidence": "low"/"medium"/"high"
- "reason": string explanation
- "manual_test": string suggesting manual test steps

Return ONLY JSON, no extra text."""
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )
            content = response.choices[0].message.content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            return json.loads(content)
        except Exception:
            return None
