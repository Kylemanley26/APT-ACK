"""
Claude-powered MITRE ATT&CK Technique Validator

Validates keyword-detected techniques and identifies missed ones using Claude API.
Requires ANTHROPIC_API_KEY environment variable.
"""

import anthropic
import json
import os
from typing import Optional


class ClaudeValidator:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")
        
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.model = "claude-sonnet-4-20250514"  # More reliable JSON output than Haiku
    
    def validate_techniques(
        self, 
        title: str, 
        content: str, 
        detected_techniques: list[dict],
        max_content_length: int = 6000
    ) -> dict:
        """
        Validate detected techniques and suggest missed ones.
        
        Args:
            title: Article title
            content: Article content
            detected_techniques: List of {'id': 'T1566', 'name': 'Phishing', 'tactic': 'Initial Access'}
            max_content_length: Truncate content to this length
        
        Returns:
            {
                'validated': [{'id': 'T1566', 'confidence': 0.95, 'reasoning': '...'}],
                'rejected': [{'id': 'T1059', 'reason': '...'}],
                'suggested': [{'id': 'T1078', 'confidence': 0.85, 'reasoning': '...'}],
                'summary': 'Brief threat summary',
                'error': None
            }
        """
        
        if not detected_techniques:
            detected_str = "None detected via keywords"
        else:
            detected_str = "\n".join([
                f"- {t['id']}: {t.get('name', 'Unknown')} ({t.get('tactic', 'Unknown')})" 
                for t in detected_techniques
            ])
        
        # Truncate content if needed
        truncated_content = content[:max_content_length]
        if len(content) > max_content_length:
            truncated_content += "\n[... content truncated ...]"
        
        prompt = f"""Analyze this threat intelligence article for MITRE ATT&CK technique mappings.

ARTICLE TITLE: {title}

ARTICLE CONTENT:
{truncated_content}

TECHNIQUES DETECTED VIA KEYWORD MATCHING:
{detected_str}

TASKS:
1. Validate each detected technique - is it actually described in the article?
2. Identify techniques missed by keyword matching
3. Provide confidence scores (0.0-1.0) based on how explicitly the technique is described
4. Write a 1-2 sentence threat summary

CONFIDENCE GUIDELINES:
- 0.9-1.0: Technique explicitly named or clearly described with specific details
- 0.7-0.9: Technique strongly implied by described behavior
- 0.5-0.7: Technique possibly relevant but not clearly described
- Below 0.5: Don't include

Respond ONLY with valid JSON (no markdown, no explanation):
{{
    "validated": [
        {{"id": "T1566", "confidence": 0.95, "reasoning": "Article explicitly describes phishing email with malicious Excel attachment"}}
    ],
    "rejected": [
        {{"id": "T1059", "reason": "PowerShell mentioned only in detection guidance, not as attack vector"}}
    ],
    "suggested": [
        {{"id": "T1078", "confidence": 0.8, "reasoning": "Attackers described using compromised employee credentials"}}
    ],
    "summary": "Threat actor used spearphishing to deliver ransomware targeting healthcare sector"
}}"""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,  # Sonnet handles longer output reliably
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = response.content[0].text.strip()
            
            # Handle potential markdown wrapping
            if response_text.startswith("```"):
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
                response_text = response_text.strip()
            
            result = json.loads(response_text)
            result['error'] = None
            return result
            
        except json.JSONDecodeError as e:
            # Retry once on JSON error
            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=1500,
                    messages=[{"role": "user", "content": prompt + "\n\nIMPORTANT: Respond ONLY with valid JSON, no markdown."}]
                )
                response_text = response.content[0].text.strip()
                if response_text.startswith("```"):
                    response_text = response_text.split("```")[1]
                    if response_text.startswith("json"):
                        response_text = response_text[4:]
                    response_text = response_text.strip()
                result = json.loads(response_text)
                result['error'] = None
                return result
            except:
                return {
                    'validated': detected_techniques,
                    'rejected': [],
                    'suggested': [],
                    'summary': None,
                    'error': f'JSON parse error: {e}'
                }
        except anthropic.APIError as e:
            return {
                'validated': detected_techniques,
                'rejected': [],
                'suggested': [],
                'summary': None,
                'error': f'API error: {e}'
            }
    
    def extract_techniques(
        self, 
        title: str, 
        content: str,
        max_content_length: int = 6000
    ) -> dict:
        """
        Extract techniques directly without prior keyword detection.
        Use this for high-value articles or when keyword detection returns nothing.
        
        Returns:
            {
                'techniques': [{'id': 'T1566', 'confidence': 0.95, 'reasoning': '...'}],
                'summary': 'Brief threat summary',
                'threat_actors': ['APT29'],
                'malware': ['Cobalt Strike'],
                'error': None
            }
        """
        
        truncated_content = content[:max_content_length]
        if len(content) > max_content_length:
            truncated_content += "\n[... content truncated ...]"
        
        prompt = f"""Extract MITRE ATT&CK techniques from this threat intelligence article.

ARTICLE TITLE: {title}

ARTICLE CONTENT:
{truncated_content}

TASKS:
1. Identify all MITRE ATT&CK Enterprise techniques described or implied
2. Extract any threat actor names mentioned
3. Extract any malware families mentioned
4. Write a 1-2 sentence threat summary

CONFIDENCE GUIDELINES:
- 0.9-1.0: Technique explicitly named or clearly described
- 0.7-0.9: Technique strongly implied by behavior
- 0.5-0.7: Technique possibly relevant
- Below 0.5: Don't include

Respond ONLY with valid JSON:
{{
    "techniques": [
        {{"id": "T1566.001", "confidence": 0.95, "reasoning": "Spearphishing attachment described"}}
    ],
    "threat_actors": ["APT29", "Cozy Bear"],
    "malware": ["Cobalt Strike", "Mimikatz"],
    "summary": "Russian APT targeted government entities via spearphishing"
}}"""

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = response.content[0].text.strip()
            
            if response_text.startswith("```"):
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
                response_text = response_text.strip()
            
            result = json.loads(response_text)
            result['error'] = None
            return result
            
        except json.JSONDecodeError as e:
            return {
                'techniques': [],
                'threat_actors': [],
                'malware': [],
                'summary': None,
                'error': f'JSON parse error: {e}'
            }
        except anthropic.APIError as e:
            return {
                'techniques': [],
                'threat_actors': [],
                'malware': [],
                'summary': None,
                'error': f'API error: {e}'
            }


# Singleton instance
_validator_instance = None

def get_claude_validator() -> Optional[ClaudeValidator]:
    """Get or create singleton ClaudeValidator instance"""
    global _validator_instance
    
    if _validator_instance is None:
        try:
            _validator_instance = ClaudeValidator()
        except ValueError:
            return None
    
    return _validator_instance


if __name__ == "__main__":
    # Test the validator
    validator = ClaudeValidator()
    
    test_title = "APT29 Targets Government Agencies with Novel Phishing Campaign"
    test_content = """
    Security researchers have uncovered a new campaign by APT29 (Cozy Bear) targeting 
    government agencies across Europe. The attackers sent spearphishing emails containing 
    malicious Word documents with embedded macros. Once executed, the macros download 
    Cobalt Strike beacons which establish persistence via scheduled tasks. The threat 
    actors then use Mimikatz to dump credentials and move laterally using stolen admin 
    accounts. Data is exfiltrated over HTTPS to attacker-controlled infrastructure.
    """
    
    # Test extraction
    print("=== Testing Direct Extraction ===")
    result = validator.extract_techniques(test_title, test_content)
    print(json.dumps(result, indent=2))
    
    # Test validation
    print("\n=== Testing Validation ===")
    detected = [
        {'id': 'T1566', 'name': 'Phishing', 'tactic': 'Initial Access'},
        {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
        {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
    ]
    result = validator.validate_techniques(test_title, test_content, detected)
    print(json.dumps(result, indent=2))
