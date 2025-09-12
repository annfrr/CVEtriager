"""
Validation Agent for CVE Triage Framework
Responsible for executing proof-of-concept exploits in sandboxed environments
"""
import docker
import logging
import time
import json
import re
from typing import Dict, Any, List, Optional
from ..config.settings import settings, AGENT_CONFIGS
from ..utils.models import AnalysisMetadata, ValidationOutput, ValidationResult, AgentResponse
from ..utils.helpers import measure_execution_time, log_agent_activity, sanitize_input

class ValidationAgent:
    """Validation Agent for PoC execution and validation"""
    
    def __init__(self):
        self.client = docker.from_env()
        self.config = AGENT_CONFIGS["validation"]
        self.logger = logging.getLogger("agent.validation")
        self.validation_tools = self.config["tools"]
        
    @measure_execution_time
    def validate_vulnerability(self, container_id: str, metadata: AnalysisMetadata, 
                             report_id: str) -> AgentResponse:
        """Validate vulnerability by executing PoC in container"""
        try:
            log_agent_activity("validation", "start_validation", {"report_id": report_id})
            
            # Get container
            container = self.client.containers.get(container_id)
            
            # Execute validation based on vulnerability type
            validation_result = self._execute_validation(container, metadata)
            
            # Analyze results
            output = self._analyze_validation_result(validation_result, metadata)
            
            log_agent_activity("validation", "complete_validation", {
                "report_id": report_id,
                "result": output.result,
                "confidence": output.confidence
            })
            
            return AgentResponse(
                success=True,
                data=output,
                execution_time=0.0,
                metadata={"validation_tools_used": validation_result.get("tools_used", [])}
            )
            
        except Exception as e:
            self.logger.error(f"Validation failed: {str(e)}")
            log_agent_activity("validation", "validation_failed", {"error": str(e)})
            return AgentResponse(
                success=False,
                error=str(e),
                execution_time=0.0
            )
    
    def _execute_validation(self, container: docker.models.containers.Container, 
                          metadata: AnalysisMetadata) -> Dict[str, Any]:
        """Execute validation based on vulnerability type"""
        vuln_type = metadata.vulnerability_type
        reproduction_steps = metadata.reproduction_steps
        
        validation_result = {
            "tools_used": [],
            "commands_executed": [],
            "outputs": [],
            "errors": [],
            "success_indicators": [],
            "failure_indicators": []
        }
        
        # Execute based on vulnerability type
        if vuln_type == "xss":
            validation_result = self._validate_xss(container, reproduction_steps, validation_result)
        elif vuln_type == "sql_injection":
            validation_result = self._validate_sql_injection(container, reproduction_steps, validation_result)
        elif vuln_type == "file_upload":
            validation_result = self._validate_file_upload(container, reproduction_steps, validation_result)
        elif vuln_type == "path_traversal":
            validation_result = self._validate_path_traversal(container, reproduction_steps, validation_result)
        elif vuln_type == "command_injection":
            validation_result = self._validate_command_injection(container, reproduction_steps, validation_result)
        elif vuln_type == "ssrf":
            validation_result = self._validate_ssrf(container, reproduction_steps, validation_result)
        else:
            validation_result = self._validate_generic(container, reproduction_steps, validation_result)
        
        return validation_result
    
    def _validate_xss(self, container: docker.models.containers.Container, 
                     steps: List[str], result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate XSS vulnerability"""
        result["tools_used"].append("curl")
        
        # Look for XSS payloads in steps
        xss_payloads = ["<script>", "javascript:", "onerror=", "onload="]
        
        for step in steps:
            if any(payload in step.lower() for payload in xss_payloads):
                # Extract URL and payload
                url_match = re.search(r'https?://[^\s]+', step)
                if url_match:
                    url = url_match.group()
                    # Execute curl request
                    command = f"curl -s '{url}'"
                    output = self._run_command(container, command)
                    result["commands_executed"].append(command)
                    result["outputs"].append(output)
                    
                    # Check for XSS indicators
                    if any(payload in output.lower() for payload in xss_payloads):
                        result["success_indicators"].append("XSS payload reflected in response")
                    else:
                        result["failure_indicators"].append("XSS payload not reflected")
        
        return result
    
    def _validate_sql_injection(self, container: docker.models.containers.Container, 
                              steps: List[str], result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SQL injection vulnerability"""
        result["tools_used"].extend(["curl", "sqlmap"])
        
        # Look for SQL injection payloads
        sql_payloads = ["'", "union", "select", "or 1=1", "sleep(", "waitfor"]
        
        for step in steps:
            if any(payload in step.lower() for payload in sql_payloads):
                # Extract URL and parameters
                url_match = re.search(r'https?://[^\s]+', step)
                if url_match:
                    url = url_match.group()
                    
                    # Test with curl first
                    command = f"curl -s '{url}'"
                    output = self._run_command(container, command)
                    result["commands_executed"].append(command)
                    result["outputs"].append(output)
                    
                    # Check for SQL error indicators
                    sql_errors = ["mysql", "sqlite", "postgresql", "sql syntax", "database error"]
                    if any(error in output.lower() for error in sql_errors):
                        result["success_indicators"].append("SQL error detected in response")
                    
                    # Try sqlmap if available
                    try:
                        sqlmap_cmd = f"sqlmap -u '{url}' --batch --dbs"
                        sqlmap_output = self._run_command(container, sqlmap_cmd)
                        result["commands_executed"].append(sqlmap_cmd)
                        result["outputs"].append(sqlmap_output)
                        
                        if "available databases" in sqlmap_output.lower():
                            result["success_indicators"].append("SQLMap confirmed SQL injection")
                    except:
                        pass
        
        return result
    
    def _validate_file_upload(self, container: docker.models.containers.Container, 
                            steps: List[str], result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate file upload vulnerability"""
        result["tools_used"].append("curl")
        
        # Look for file upload indicators
        upload_indicators = ["upload", "file", "multipart", "form-data"]
        
        for step in steps:
            if any(indicator in step.lower() for indicator in upload_indicators):
                # Create test file
                test_file = "/tmp/test.php"
                php_payload = "<?php echo 'File upload test'; ?>"
                self._run_command(container, f"echo '{php_payload}' > {test_file}")
                
                # Try to upload file
                command = f"curl -X POST -F 'file=@{test_file}' '{step}'"
                output = self._run_command(container, command)
                result["commands_executed"].append(command)
                result["outputs"].append(output)
                
                # Check for success indicators
                if "upload" in output.lower() and "success" in output.lower():
                    result["success_indicators"].append("File upload successful")
                else:
                    result["failure_indicators"].append("File upload failed")
        
        return result
    
    def _validate_path_traversal(self, container: docker.models.containers.Container, 
                               steps: List[str], result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate path traversal vulnerability"""
        result["tools_used"].append("curl")
        
        # Look for path traversal payloads
        traversal_payloads = ["../", "..\\", "/etc/passwd", "windows/system32"]
        
        for step in steps:
            if any(payload in step for payload in traversal_payloads):
                # Extract URL
                url_match = re.search(r'https?://[^\s]+', step)
                if url_match:
                    url = url_match.group()
                    
                    # Test path traversal
                    command = f"curl -s '{url}'"
                    output = self._run_command(container, command)
                    result["commands_executed"].append(command)
                    result["outputs"].append(output)
                    
                    # Check for file content indicators
                    file_indicators = ["root:", "bin:", "daemon:", "system32", "boot.ini"]
                    if any(indicator in output for indicator in file_indicators):
                        result["success_indicators"].append("Path traversal successful - file content exposed")
                    else:
                        result["failure_indicators"].append("Path traversal failed")
        
        return result
    
    def _validate_command_injection(self, container: docker.models.containers.Container, 
                                  steps: List[str], result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate command injection vulnerability"""
        result["tools_used"].append("curl")
        
        # Look for command injection payloads
        cmd_payloads = [";", "|", "&", "`", "$(", "whoami", "id", "ls"]
        
        for step in steps:
            if any(payload in step for payload in cmd_payloads):
                # Extract URL
                url_match = re.search(r'https?://[^\s]+', step)
                if url_match:
                    url = url_match.group()
                    
                    # Test command injection
                    command = f"curl -s '{url}'"
                    output = self._run_command(container, command)
                    result["commands_executed"].append(command)
                    result["outputs"].append(output)
                    
                    # Check for command execution indicators
                    cmd_indicators = ["uid=", "gid=", "root", "www-data", "apache"]
                    if any(indicator in output for indicator in cmd_indicators):
                        result["success_indicators"].append("Command injection successful")
                    else:
                        result["failure_indicators"].append("Command injection failed")
        
        return result
    
    def _validate_ssrf(self, container: docker.models.containers.Container, 
                      steps: List[str], result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SSRF vulnerability"""
        result["tools_used"].extend(["curl", "netcat"])
        
        # Look for SSRF indicators
        ssrf_indicators = ["http://", "https://", "file://", "gopher://", "dict://"]
        
        for step in steps:
            if any(indicator in step.lower() for indicator in ssrf_indicators):
                # Extract URL
                url_match = re.search(r'https?://[^\s]+', step)
                if url_match:
                    url = url_match.group()
                    
                    # Test SSRF
                    command = f"curl -s '{url}'"
                    output = self._run_command(container, command)
                    result["commands_executed"].append(command)
                    result["outputs"].append(output)
                    
                    # Check for SSRF indicators
                    if "connection" in output.lower() or "timeout" in output.lower():
                        result["success_indicators"].append("SSRF request made")
                    else:
                        result["failure_indicators"].append("SSRF request failed")
        
        return result
    
    def _validate_generic(self, container: docker.models.containers.Container, 
                        steps: List[str], result: Dict[str, Any]) -> Dict[str, Any]:
        """Generic validation for unknown vulnerability types"""
        result["tools_used"].append("curl")
        
        for step in steps:
            # Look for URLs
            url_match = re.search(r'https?://[^\s]+', step)
            if url_match:
                url = url_match.group()
                command = f"curl -s '{url}'"
                output = self._run_command(container, command)
                result["commands_executed"].append(command)
                result["outputs"].append(output)
        
        return result
    
    def _run_command(self, container: docker.models.containers.Container, command: str) -> str:
        """Run command in container with timeout"""
        try:
            result = container.exec_run(
                command, 
                stdout=True, 
                stderr=True,
                timeout=self.config["timeout"]
            )
            return result.output.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Command failed: {command}, Error: {e}")
            return f"Command failed: {str(e)}"
    
    def _analyze_validation_result(self, result: Dict[str, Any], 
                                 metadata: AnalysisMetadata) -> ValidationOutput:
        """Analyze validation results and determine outcome"""
        success_indicators = result.get("success_indicators", [])
        failure_indicators = result.get("failure_indicators", [])
        
        # Determine validation result
        if success_indicators and not failure_indicators:
            validation_result = ValidationResult.SUCCESS
            confidence = 0.9
        elif failure_indicators and not success_indicators:
            validation_result = ValidationResult.FAILURE
            confidence = 0.8
        elif success_indicators and failure_indicators:
            validation_result = ValidationResult.INCONCLUSIVE
            confidence = 0.5
        else:
            validation_result = ValidationResult.INCONCLUSIVE
            confidence = 0.3
        
        # Calculate execution time (simplified)
        execution_time = len(result.get("commands_executed", [])) * 2.0
        
        return ValidationOutput(
            result=validation_result,
            execution_logs=result.get("outputs", []),
            artifacts={
                "commands_executed": result.get("commands_executed", []),
                "success_indicators": success_indicators,
                "failure_indicators": failure_indicators,
                "tools_used": result.get("tools_used", [])
            },
            execution_time=execution_time,
            confidence=confidence
        )
