"""
Analysis Agent for CVE Triage Framework
Responsible for interpreting vulnerability reports and extracting structured metadata
"""
import json
import logging
from typing import Dict, Any, List, Optional
from openai import OpenAI
from ..config.settings import settings, AGENT_CONFIGS, VULNERABILITY_TYPES
from ..utils.models import RawReport, AnalysisMetadata, VulnerabilityType, AgentResponse
from ..utils.helpers import measure_execution_time, log_agent_activity, sanitize_input

class AnalysisAgent:
    """Analysis Agent for vulnerability report interpretation"""
    
    def __init__(self):
        self.client = OpenAI(api_key=settings.openai_api_key)
        self.config = AGENT_CONFIGS["analysis"]
        self.logger = logging.getLogger("agent.analysis")
        self.vulnerability_types = VULNERABILITY_TYPES
        
    @measure_execution_time
    def analyze_report(self, report: RawReport) -> AgentResponse:
        """Analyze vulnerability report and extract structured metadata"""
        try:
            log_agent_activity("analysis", "start_analysis", {"report_id": report.title})
            
            # Prepare the analysis prompt
            analysis_prompt = self._create_analysis_prompt(report)
            
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=self.config["model"],
                messages=[
                    {"role": "system", "content": self.config["system_prompt"]},
                    {"role": "user", "content": analysis_prompt}
                ],
                temperature=self.config["temperature"],
                max_tokens=self.config["max_tokens"]
            )
            
            # Parse the response
            analysis_result = self._parse_analysis_response(response.choices[0].message.content)
            
            # Create structured metadata
            metadata = self._create_metadata(analysis_result, report)
            
            log_agent_activity("analysis", "complete_analysis", {
                "vulnerability_type": metadata.vulnerability_type,
                "confidence": metadata.confidence_score
            })
            
            return AgentResponse(
                success=True,
                data=metadata,
                execution_time=0.0,  # Will be set by decorator
                metadata={"tokens_used": response.usage.total_tokens}
            )
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            log_agent_activity("analysis", "analysis_failed", {"error": str(e)})
            return AgentResponse(
                success=False,
                error=str(e),
                execution_time=0.0
            )
    
    def _create_analysis_prompt(self, report: RawReport) -> str:
        """Create analysis prompt for the LLM"""
        prompt = f"""
        Analyze the following vulnerability report and extract structured information:

        TITLE: {report.title}
        DESCRIPTION: {report.description}
        STEPS TO REPRODUCE: {report.steps_to_reproduce}
        PAYLOAD: {report.payload or 'Not provided'}
        AFFECTED URL: {report.affected_url or 'Not provided'}
        AFFECTED SOFTWARE: {report.affected_software or 'Not provided'}
        SOFTWARE VERSION: {report.software_version or 'Not provided'}

        Please provide a JSON response with the following structure:
        {{
            "vulnerability_type": "one of: xss, sql_injection, file_upload, path_traversal, command_injection, authentication, authorization, ssrf, file_disclosure, unknown",
            "affected_components": ["list of affected components"],
            "reproduction_steps": ["step1", "step2", "step3"],
            "configuration_parameters": {{
                "required_packages": ["list of required packages"],
                "environment_setup": "description of environment setup needed",
                "network_config": "any network configuration needed",
                "file_system": "any file system setup needed"
            }},
            "confidence_score": 0.0-1.0,
            "requires_manual_review": true/false,
            "environment_requirements": {{
                "base_image": "recommended base image",
                "packages": ["list of packages to install"],
                "services": ["list of services to run"],
                "ports": [list of ports to expose]
            }},
            "validation_instructions": ["specific instructions for validation"],
            "reasoning": "explanation of the analysis"
        }}

        Focus on:
        1. Identifying the vulnerability type accurately
        2. Extracting clear reproduction steps
        3. Determining environment requirements
        4. Assessing confidence in the analysis
        5. Flagging if manual review is needed
        """
        return prompt
    
    def _parse_analysis_response(self, response_text: str) -> Dict[str, Any]:
        """Parse LLM response into structured data"""
        try:
            # Extract JSON from response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx == -1 or end_idx == 0:
                raise ValueError("No JSON found in response")
            
            json_str = response_text[start_idx:end_idx]
            return json.loads(json_str)
            
        except Exception as e:
            self.logger.error(f"Failed to parse analysis response: {e}")
            # Return default structure
            return {
                "vulnerability_type": "unknown",
                "affected_components": [],
                "reproduction_steps": [],
                "configuration_parameters": {},
                "confidence_score": 0.0,
                "requires_manual_review": True,
                "environment_requirements": {},
                "validation_instructions": [],
                "reasoning": "Failed to parse response"
            }
    
    def _create_metadata(self, analysis_result: Dict[str, Any], report: RawReport) -> AnalysisMetadata:
        """Create AnalysisMetadata from parsed result"""
        # Map vulnerability type
        vuln_type_str = analysis_result.get("vulnerability_type", "unknown")
        try:
            vulnerability_type = VulnerabilityType(vuln_type_str)
        except ValueError:
            vulnerability_type = VulnerabilityType.UNKNOWN
        
        # Extract components
        affected_components = analysis_result.get("affected_components", [])
        if report.affected_software:
            affected_components.append(report.affected_software)
        if report.affected_url:
            affected_components.append(report.affected_url)
        
        # Extract reproduction steps
        reproduction_steps = analysis_result.get("reproduction_steps", [])
        if not reproduction_steps and report.steps_to_reproduce:
            reproduction_steps = [report.steps_to_reproduce]
        
        # Extract configuration parameters
        config_params = analysis_result.get("configuration_parameters", {})
        
        # Get confidence score
        confidence_score = float(analysis_result.get("confidence_score", 0.0))
        
        # Determine if manual review is required
        requires_manual_review = analysis_result.get("requires_manual_review", False)
        if confidence_score < settings.confidence_threshold:
            requires_manual_review = True
        
        # Extract environment requirements
        env_requirements = analysis_result.get("environment_requirements", {})
        
        # Extract validation instructions
        validation_instructions = analysis_result.get("validation_instructions", [])
        
        return AnalysisMetadata(
            vulnerability_type=vulnerability_type,
            affected_components=affected_components,
            reproduction_steps=reproduction_steps,
            configuration_parameters=config_params,
            confidence_score=confidence_score,
            requires_manual_review=requires_manual_review,
            environment_requirements=env_requirements,
            validation_instructions=validation_instructions
        )
    
    def validate_analysis(self, metadata: AnalysisMetadata) -> bool:
        """Validate analysis metadata completeness"""
        required_fields = [
            metadata.vulnerability_type,
            metadata.affected_components,
            metadata.reproduction_steps
        ]
        
        return all(field for field in required_fields)
    
    def get_environment_spec(self, metadata: AnalysisMetadata) -> Dict[str, Any]:
        """Generate environment specification from metadata"""
        env_req = metadata.environment_requirements
        
        return {
            "base_image": env_req.get("base_image", "ubuntu:22.04"),
            "packages": env_req.get("packages", []),
            "services": env_req.get("services", []),
            "network_config": env_req.get("network_config", {}),
            "file_system": env_req.get("file_system", {}),
            "environment_variables": env_req.get("environment_variables", {}),
            "ports": env_req.get("ports", [])
        }
