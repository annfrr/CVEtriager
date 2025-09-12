"""
Configuration settings for the CVE Triage Framework
"""
import os
from typing import Dict, Any

class Settings:
    def __init__(self):
        # OpenAI API Configuration
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "")
        self.openai_model = os.getenv("OPENAI_MODEL", "gpt-4")
        self.openai_temperature = float(os.getenv("OPENAI_TEMPERATURE", "0.1"))
        self.openai_max_tokens = int(os.getenv("OPENAI_MAX_TOKENS", "2000"))
        
        # Docker Configuration
        self.docker_timeout = int(os.getenv("DOCKER_TIMEOUT", "300"))
        self.docker_memory_limit = os.getenv("DOCKER_MEMORY_LIMIT", "1g")
        self.docker_cpu_limit = os.getenv("DOCKER_CPU_LIMIT", "1.0")
        
        # Pipeline Configuration
        self.confidence_threshold = float(os.getenv("CONFIDENCE_THRESHOLD", "0.7"))
        self.poc_timeout = int(os.getenv("POC_TIMEOUT", "180"))
        self.max_retries = int(os.getenv("MAX_RETRIES", "3"))
        
        # Logging Configuration
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_file = os.getenv("LOG_FILE", "logs/triage.log")
        
        # Database Configuration (for future use)
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./triage.db")
        
        # CVSS Configuration
        self.cvss_version = os.getenv("CVSS_VERSION", "3.1")

# Global settings instance
settings = Settings()

# Agent-specific configurations
AGENT_CONFIGS = {
    "analysis": {
        "model": settings.openai_model,
        "temperature": settings.openai_temperature,
        "max_tokens": settings.openai_max_tokens,
        "system_prompt": "You are an expert cybersecurity analyst specializing in vulnerability assessment and CVE triage."
    },
    "deployment": {
        "base_image": "ubuntu:22.04",
        "timeout": settings.docker_timeout,
        "memory_limit": settings.docker_memory_limit,
        "cpu_limit": settings.docker_cpu_limit
    },
    "validation": {
        "timeout": settings.poc_timeout,
        "max_retries": settings.max_retries,
        "tools": ["curl", "sqlmap", "nmap", "nikto", "gobuster"]
    },
    "scoring": {
        "cvss_version": settings.cvss_version,
        "model": settings.openai_model,
        "temperature": 0.0  # More deterministic for scoring
    }
}

# Vulnerability type mappings
VULNERABILITY_TYPES = {
    "xss": ["Cross-Site Scripting", "XSS", "Reflected XSS", "Stored XSS", "DOM-based XSS"],
    "sql_injection": ["SQL Injection", "SQLi", "Blind SQL Injection", "Time-based SQL Injection"],
    "file_upload": ["Insecure File Upload", "Unrestricted File Upload", "File Upload Vulnerability"],
    "path_traversal": ["Path Traversal", "Directory Traversal", "Local File Inclusion"],
    "command_injection": ["Command Injection", "OS Command Injection", "Code Injection"],
    "authentication": ["Broken Authentication", "Authentication Bypass", "Session Management"],
    "authorization": ["Insecure Direct Object Reference", "IDOR", "Authorization Bypass"],
    "ssrf": ["Server-Side Request Forgery", "SSRF"],
    "file_disclosure": ["File Disclosure", "Information Disclosure", "Sensitive Data Exposure"]
}

# CVSS Base Metrics
CVSS_BASE_METRICS = {
    "attack_vector": ["Network", "Adjacent", "Local", "Physical"],
    "attack_complexity": ["Low", "High"],
    "privileges_required": ["None", "Low", "High"],
    "user_interaction": ["None", "Required"],
    "scope": ["Unchanged", "Changed"],
    "confidentiality": ["None", "Low", "High"],
    "integrity": ["None", "Low", "High"],
    "availability": ["None", "Low", "High"]
}
