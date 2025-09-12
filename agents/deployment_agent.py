"""
Deployment Agent for CVE Triage Framework
Responsible for setting up sandboxed environments for vulnerability testing
"""
import docker
import logging
import time
import os
from typing import Dict, Any, List, Optional
from ..config.settings import settings, AGENT_CONFIGS
from ..utils.models import AnalysisMetadata, EnvironmentSpec, AgentResponse
from ..utils.helpers import measure_execution_time, log_agent_activity, create_docker_command

class DeploymentAgent:
    """Deployment Agent for environment setup and management"""
    
    def __init__(self):
        self.client = docker.from_env()
        self.config = AGENT_CONFIGS["deployment"]
        self.logger = logging.getLogger("agent.deployment")
        self.active_containers = {}
        
    @measure_execution_time
    def deploy_environment(self, metadata: AnalysisMetadata, report_id: str) -> AgentResponse:
        """Deploy sandboxed environment based on analysis metadata"""
        try:
            log_agent_activity("deployment", "start_deployment", {"report_id": report_id})
            
            # Generate environment specification
            env_spec = self._generate_environment_spec(metadata)
            
            # Create and start container
            container = self._create_container(env_spec, report_id)
            
            # Install packages and configure environment
            self._setup_environment(container, env_spec)
            
            # Store container reference
            self.active_containers[report_id] = container
            
            log_agent_activity("deployment", "complete_deployment", {
                "report_id": report_id,
                "container_id": container.short_id
            })
            
            return AgentResponse(
                success=True,
                data={
                    "container_id": container.id,
                    "container_name": container.name,
                    "environment_spec": env_spec,
                    "status": "ready"
                },
                execution_time=0.0,
                metadata={"base_image": env_spec.base_image}
            )
            
        except Exception as e:
            self.logger.error(f"Deployment failed: {str(e)}")
            log_agent_activity("deployment", "deployment_failed", {"error": str(e)})
            return AgentResponse(
                success=False,
                error=str(e),
                execution_time=0.0
            )
    
    def _generate_environment_spec(self, metadata: AnalysisMetadata) -> EnvironmentSpec:
        """Generate environment specification from metadata"""
        env_req = metadata.environment_requirements
        
        # Default packages based on vulnerability type
        default_packages = self._get_default_packages(metadata.vulnerability_type)
        
        # Merge with requirements from analysis
        packages = list(set(default_packages + env_req.get("packages", [])))
        
        return EnvironmentSpec(
            base_image=env_req.get("base_image", self.config["base_image"]),
            packages=packages,
            services=env_req.get("services", []),
            network_config=env_req.get("network_config", {}),
            file_system=env_req.get("file_system", {}),
            environment_variables=env_req.get("environment_variables", {}),
            ports=env_req.get("ports", [])
        )
    
    def _get_default_packages(self, vulnerability_type: str) -> List[str]:
        """Get default packages based on vulnerability type"""
        package_map = {
            "xss": ["curl", "wget", "python3", "python3-pip", "chromium-browser", "xvfb"],
            "sql_injection": ["curl", "wget", "python3", "python3-pip", "sqlmap", "mysql-client"],
            "file_upload": ["curl", "wget", "python3", "python3-pip", "apache2", "php"],
            "path_traversal": ["curl", "wget", "python3", "python3-pip", "apache2", "nginx"],
            "command_injection": ["curl", "wget", "python3", "python3-pip", "netcat", "nmap"],
            "authentication": ["curl", "wget", "python3", "python3-pip", "apache2", "php"],
            "authorization": ["curl", "wget", "python3", "python3-pip", "apache2", "php"],
            "ssrf": ["curl", "wget", "python3", "python3-pip", "netcat", "nmap"],
            "file_disclosure": ["curl", "wget", "python3", "python3-pip", "apache2", "nginx"]
        }
        
        return package_map.get(vulnerability_type, ["curl", "wget", "python3", "python3-pip"])
    
    def _create_container(self, env_spec: EnvironmentSpec, report_id: str) -> docker.models.containers.Container:
        """Create Docker container with specified configuration"""
        container_name = f"cve-triage-{report_id}"
        
        # Remove existing container if it exists
        try:
            existing = self.client.containers.get(container_name)
            existing.remove(force=True)
        except docker.errors.NotFound:
            pass
        
        # Create container
        container = self.client.containers.run(
            image=env_spec.base_image,
            name=container_name,
            detach=True,
            stdin_open=True,
            tty=True,
            mem_limit=self.config["memory_limit"],
            cpu_quota=int(float(self.config["cpu_limit"]) * 100000),
            environment=env_spec.environment_variables,
            ports={port: port for port in env_spec.ports} if env_spec.ports else None,
            command="/bin/bash"
        )
        
        # Wait for container to be ready
        time.sleep(2)
        
        return container
    
    def _setup_environment(self, container: docker.models.containers.Container, env_spec: EnvironmentSpec):
        """Setup environment inside container"""
        # Update package lists
        self._run_command(container, "apt-get update")
        
        # Install packages
        if env_spec.packages:
            packages_str = " ".join(env_spec.packages)
            self._run_command(container, f"apt-get install -y {packages_str}")
        
        # Install Python packages if needed
        python_packages = ["requests", "beautifulsoup4", "selenium", "lxml"]
        for package in python_packages:
            self._run_command(container, f"pip3 install {package}")
        
        # Setup file system
        for path, content in env_spec.file_system.items():
            if isinstance(content, str):
                self._run_command(container, f"mkdir -p {os.path.dirname(path)}")
                self._run_command(container, f"echo '{content}' > {path}")
        
        # Start services
        for service in env_spec.services:
            self._run_command(container, f"service {service} start")
    
    def _run_command(self, container: docker.models.containers.Container, command: str) -> str:
        """Run command in container and return output"""
        try:
            result = container.exec_run(command, stdout=True, stderr=True)
            return result.output.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Command failed: {command}, Error: {e}")
            return ""
    
    def get_container(self, report_id: str) -> Optional[docker.models.containers.Container]:
        """Get container by report ID"""
        return self.active_containers.get(report_id)
    
    def cleanup_environment(self, report_id: str) -> bool:
        """Cleanup environment for specific report"""
        try:
            if report_id in self.active_containers:
                container = self.active_containers[report_id]
                container.remove(force=True)
                del self.active_containers[report_id]
                log_agent_activity("deployment", "cleanup_complete", {"report_id": report_id})
                return True
            return False
        except Exception as e:
            self.logger.error(f"Cleanup failed for {report_id}: {e}")
            return False
    
    def cleanup_all_environments(self):
        """Cleanup all active environments"""
        for report_id in list(self.active_containers.keys()):
            self.cleanup_environment(report_id)
    
    def get_container_status(self, report_id: str) -> Dict[str, Any]:
        """Get container status information"""
        if report_id not in self.active_containers:
            return {"status": "not_found"}
        
        container = self.active_containers[report_id]
        return {
            "status": container.status,
            "id": container.short_id,
            "name": container.name,
            "created": container.attrs["Created"],
            "state": container.attrs["State"]
        }
