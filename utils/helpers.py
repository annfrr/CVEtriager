"""
Helper functions for the CVE Triage Framework
"""
import time
import logging
import json
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime

def setup_logging(log_level: str = "INFO", log_file: str = "logs/triage.log") -> logging.Logger:
    """Setup logging configuration"""
    import os
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def generate_report_id(report_data: Dict[str, Any]) -> str:
    """Generate unique report ID based on content"""
    content = json.dumps(report_data, sort_keys=True)
    return hashlib.md5(content.encode()).hexdigest()[:12]

def measure_execution_time(func):
    """Decorator to measure function execution time"""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        execution_time = time.time() - start_time
        if hasattr(result, 'execution_time'):
            result.execution_time = execution_time
        return result
    return wrapper

def validate_confidence_threshold(confidence: float, threshold: float = 0.7) -> bool:
    """Validate if confidence score meets threshold"""
    return confidence >= threshold

def sanitize_input(text: str) -> str:
    """Sanitize input text for security"""
    if not text:
        return ""
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '|', '`', '$']
    for char in dangerous_chars:
        text = text.replace(char, '')
    return text.strip()

def extract_url_domain(url: str) -> str:
    """Extract domain from URL"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return ""

def format_cvss_vector(cvss_data: Dict[str, str]) -> str:
    """Format CVSS vector string"""
    vector_parts = []
    for metric, value in cvss_data.items():
        if metric in ['attack_vector', 'attack_complexity', 'privileges_required', 
                     'user_interaction', 'scope', 'confidentiality', 'integrity', 'availability']:
            vector_parts.append(f"{metric.upper().replace('_', '')}:{value[0].upper()}")
    return "/".join(vector_parts)

def parse_cvss_vector(vector_string: str) -> Dict[str, str]:
    """Parse CVSS vector string into components"""
    cvss_data = {}
    if not vector_string:
        return cvss_data
    
    parts = vector_string.split("/")
    for part in parts:
        if ":" in part:
            metric, value = part.split(":", 1)
            metric = metric.lower().replace("_", "_")
            cvss_data[metric] = value.upper()
    
    return cvss_data

def create_docker_command(image: str, command: str, volumes: List[str] = None, 
                         environment: Dict[str, str] = None) -> List[str]:
    """Create Docker run command"""
    cmd = ["docker", "run", "--rm"]
    
    if volumes:
        for volume in volumes:
            cmd.extend(["-v", volume])
    
    if environment:
        for key, value in environment.items():
            cmd.extend(["-e", f"{key}={value}"])
    
    cmd.append(image)
    cmd.extend(command.split())
    
    return cmd

def log_agent_activity(agent_name: str, action: str, details: Dict[str, Any] = None):
    """Log agent activity for audit trail"""
    logger = logging.getLogger(f"agent.{agent_name}")
    log_data = {
        "agent": agent_name,
        "action": action,
        "timestamp": datetime.now().isoformat(),
        "details": details or {}
    }
    logger.info(f"Agent activity: {json.dumps(log_data)}")

def validate_environment_requirements(requirements: Dict[str, Any]) -> bool:
    """Validate environment requirements are met"""
    required_keys = ['base_image', 'packages']
    return all(key in requirements for key in required_keys)

def create_artifact_path(report_id: str, artifact_type: str, filename: str) -> str:
    """Create standardized artifact path"""
    return f"artifacts/{report_id}/{artifact_type}/{filename}"

def save_artifact(content: Any, path: str) -> bool:
    """Save artifact to filesystem"""
    try:
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        if isinstance(content, (dict, list)):
            with open(path, 'w') as f:
                json.dump(content, f, indent=2)
        else:
            with open(path, 'w') as f:
                f.write(str(content))
        return True
    except Exception as e:
        logging.error(f"Failed to save artifact {path}: {e}")
        return False
