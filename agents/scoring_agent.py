"""
Scoring Agent for CVE Triage Framework
Responsible for calculating CVSS scores and generating severity assessments
"""
import json
import logging
from typing import Dict, Any, List, Optional
from openai import OpenAI
from ..config.settings import settings, AGENT_CONFIGS
from ..utils.models import AnalysisMetadata, ValidationOutput, CVSSVector, CVSSScore, AgentResponse
from ..utils.cvss_calculator import CVSSCalculator
from ..utils.helpers import measure_execution_time, log_agent_activity

class ScoringAgent:
    """Scoring Agent for CVSS calculation and severity assessment"""
    
    def __init__(self):
        self.client = OpenAI(api_key=settings.openai_api_key)
        self.config = AGENT_CONFIGS["scoring"]
        self.logger = logging.getLogger("agent.scoring")
        self.cvss_calculator = CVSSCalculator()
        
    @measure_execution_time
    def calculate_cvss_score(self, metadata: AnalysisMetadata, 
                           validation_output: ValidationOutput) -> AgentResponse:
        """Calculate CVSS score based on analysis and validation results"""
        try:
            log_agent_activity("scoring", "start_scoring", {
                "vulnerability_type": metadata.vulnerability_type
            })
            
            # Generate CVSS vector using LLM
            cvss_vector = self._generate_cvss_vector(metadata, validation_output)
            
            # Calculate CVSS score
            cvss_score = self.cvss_calculator.calculate_score(cvss_vector)
            
            log_agent_activity("scoring", "complete_scoring", {
                "base_score": cvss_score.base_score,
                "vector": cvss_vector.dict()
            })
            
            return AgentResponse(
                success=True,
                data=cvss_score,
                execution_time=0.0,
                metadata={"cvss_version": self.config["cvss_version"]}
            )
            
        except Exception as e:
            self.logger.error(f"Scoring failed: {str(e)}")
            log_agent_activity("scoring", "scoring_failed", {"error": str(e)})
            return AgentResponse(
                success=False,
                error=str(e),
                execution_time=0.0
            )
    
    def _generate_cvss_vector(self, metadata: AnalysisMetadata, 
                            validation_output: ValidationOutput) -> CVSSVector:
        """Generate CVSS vector using LLM analysis"""
        
        # Prepare scoring prompt
        scoring_prompt = self._create_scoring_prompt(metadata, validation_output)
        
        # Call OpenAI API
        response = self.client.chat.completions.create(
            model=self.config["model"],
            messages=[
                {"role": "system", "content": self._get_system_prompt()},
                {"role": "user", "content": scoring_prompt}
            ],
            temperature=self.config["temperature"],
            max_tokens=1000
        )
        
        # Parse response
        cvss_data = self._parse_cvss_response(response.choices[0].message.content)
        
        # Create CVSS vector
        return CVSSVector(**cvss_data)
    
    def _get_system_prompt(self) -> str:
        """Get system prompt for CVSS scoring"""
        return """
        You are an expert cybersecurity analyst specializing in CVSS 3.1 scoring.
        Your task is to analyze vulnerability information and assign appropriate CVSS metrics.
        
        CVSS 3.1 Base Metrics:
        - Attack Vector (AV): N=Network, A=Adjacent, L=Local, P=Physical
        - Attack Complexity (AC): L=Low, H=High
        - Privileges Required (PR): N=None, L=Low, H=High
        - User Interaction (UI): N=None, R=Required
        - Scope (S): U=Unchanged, C=Changed
        - Confidentiality (C): N=None, L=Low, H=High
        - Integrity (I): N=None, L=Low, H=High
        - Availability (A): N=None, L=Low, H=High
        
        Provide a JSON response with the CVSS vector and brief justification for each metric.
        """
    
    def _create_scoring_prompt(self, metadata: AnalysisMetadata, 
                             validation_output: ValidationOutput) -> str:
        """Create scoring prompt for LLM"""
        
        # Extract key information
        vuln_type = metadata.vulnerability_type
        validation_result = validation_output.result
        confidence = validation_output.confidence
        artifacts = validation_output.artifacts
        
        # Build context
        context = f"""
        Vulnerability Analysis:
        - Type: {vuln_type}
        - Validation Result: {validation_result}
        - Validation Confidence: {confidence}
        - Affected Components: {', '.join(metadata.affected_components)}
        
        Validation Details:
        - Success Indicators: {artifacts.get('success_indicators', [])}
        - Failure Indicators: {artifacts.get('failure_indicators', [])}
        - Tools Used: {artifacts.get('tools_used', [])}
        - Commands Executed: {len(artifacts.get('commands_executed', []))} commands
        """
        
        prompt = f"""
        {context}
        
        Based on this information, provide a CVSS 3.1 vector in JSON format:
        
        {{
            "attack_vector": "N|A|L|P",
            "attack_complexity": "L|H",
            "privileges_required": "N|L|H",
            "user_interaction": "N|R",
            "scope": "U|C",
            "confidentiality": "N|L|H",
            "integrity": "N|L|H",
            "availability": "N|L|H",
            "reasoning": {{
                "attack_vector": "explanation",
                "attack_complexity": "explanation",
                "privileges_required": "explanation",
                "user_interaction": "explanation",
                "scope": "explanation",
                "confidentiality": "explanation",
                "integrity": "explanation",
                "availability": "explanation"
            }}
        }}
        
        Consider:
        1. How the vulnerability can be exploited (network, local, etc.)
        2. Complexity of the attack
        3. Privileges needed
        4. User interaction required
        5. Impact on confidentiality, integrity, and availability
        6. Whether the scope is changed or unchanged
        """
        
        return prompt
    
    def _parse_cvss_response(self, response_text: str) -> Dict[str, Any]:
        """Parse LLM response to extract CVSS vector"""
        try:
            # Extract JSON from response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx == -1 or end_idx == 0:
                raise ValueError("No JSON found in response")
            
            json_str = response_text[start_idx:end_idx]
            cvss_data = json.loads(json_str)
            
            # Validate and clean the data
            return self._validate_cvss_data(cvss_data)
            
        except Exception as e:
            self.logger.error(f"Failed to parse CVSS response: {e}")
            # Return default conservative vector
            return self._get_default_cvss_vector()
    
    def _validate_cvss_data(self, cvss_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and clean CVSS data"""
        valid_values = {
            "attack_vector": ["N", "A", "L", "P"],
            "attack_complexity": ["L", "H"],
            "privileges_required": ["N", "L", "H"],
            "user_interaction": ["N", "R"],
            "scope": ["U", "C"],
            "confidentiality": ["N", "L", "H"],
            "integrity": ["N", "L", "H"],
            "availability": ["N", "L", "H"]
        }
        
        # Clean and validate each metric
        cleaned_data = {}
        for metric, valid_options in valid_values.items():
            value = cvss_data.get(metric, "N").upper()
            if value in valid_options:
                cleaned_data[metric] = value
            else:
                # Use default value
                cleaned_data[metric] = valid_options[0]
        
        return cleaned_data
    
    def _get_default_cvss_vector(self) -> Dict[str, str]:
        """Get default conservative CVSS vector"""
        return {
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "N",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "L",
            "availability": "N"
        }
    
    def get_severity_level(self, base_score: float) -> str:
        """Get severity level from CVSS base score"""
        if base_score >= 9.0:
            return "Critical"
        elif base_score >= 7.0:
            return "High"
        elif base_score >= 4.0:
            return "Medium"
        elif base_score >= 0.1:
            return "Low"
        else:
            return "None"
    
    def generate_severity_report(self, cvss_score: CVSSScore, 
                               metadata: AnalysisMetadata) -> Dict[str, Any]:
        """Generate comprehensive severity report"""
        severity_level = self.get_severity_level(cvss_score.base_score)
        
        return {
            "severity_level": severity_level,
            "base_score": cvss_score.base_score,
            "cvss_vector": cvss_score.vector.dict(),
            "justification": cvss_score.justification,
            "vulnerability_type": metadata.vulnerability_type,
            "affected_components": metadata.affected_components,
            "recommendations": self._get_recommendations(severity_level, metadata.vulnerability_type)
        }
    
    def _get_recommendations(self, severity_level: str, vuln_type: str) -> List[str]:
        """Get remediation recommendations based on severity and type"""
        recommendations = []
        
        # Severity-based recommendations
        if severity_level == "Critical":
            recommendations.extend([
                "Immediate patching required",
                "Consider temporary service shutdown",
                "Implement emergency response procedures"
            ])
        elif severity_level == "High":
            recommendations.extend([
                "Priority patching within 24-48 hours",
                "Implement additional monitoring",
                "Review access controls"
            ])
        elif severity_level == "Medium":
            recommendations.extend([
                "Schedule patching within 1-2 weeks",
                "Implement compensating controls",
                "Regular security assessments"
            ])
        else:
            recommendations.extend([
                "Include in next maintenance window",
                "Monitor for exploitation attempts",
                "Regular security reviews"
            ])
        
        # Type-specific recommendations
        type_recommendations = {
            "xss": ["Implement Content Security Policy", "Input validation and output encoding"],
            "sql_injection": ["Use parameterized queries", "Implement WAF rules"],
            "file_upload": ["File type validation", "Virus scanning", "Secure file storage"],
            "path_traversal": ["Path validation", "Chroot jail implementation"],
            "command_injection": ["Input sanitization", "Use safe APIs"],
            "authentication": ["Multi-factor authentication", "Strong password policies"],
            "authorization": ["Principle of least privilege", "Regular access reviews"],
            "ssrf": ["URL validation", "Network segmentation"],
            "file_disclosure": ["Access controls", "File system permissions"]
        }
        
        if vuln_type in type_recommendations:
            recommendations.extend(type_recommendations[vuln_type])
        
        return recommendations
