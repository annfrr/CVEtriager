"""
Data models for the CVE Triage Framework
"""
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

class VulnerabilityType(str, Enum):
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    FILE_UPLOAD = "file_upload"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    SSRF = "ssrf"
    FILE_DISCLOSURE = "file_disclosure"
    UNKNOWN = "unknown"

class ValidationResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    INCONCLUSIVE = "inconclusive"
    FALSE_POSITIVE = "false_positive"

class RawReport(BaseModel):
    """Raw vulnerability report input"""
    title: str
    description: str
    steps_to_reproduce: str
    payload: Optional[str] = None
    affected_url: Optional[str] = None
    affected_software: Optional[str] = None
    software_version: Optional[str] = None
    reporter: Optional[str] = None
    submission_date: Optional[datetime] = None
    additional_info: Optional[Dict[str, Any]] = None

class AnalysisMetadata(BaseModel):
    """Structured metadata extracted by Analysis Agent"""
    vulnerability_type: VulnerabilityType
    affected_components: List[str]
    reproduction_steps: List[str]
    configuration_parameters: Dict[str, Any]
    confidence_score: float = Field(ge=0.0, le=1.0)
    requires_manual_review: bool = False
    environment_requirements: Dict[str, Any]
    validation_instructions: List[str]

class EnvironmentSpec(BaseModel):
    """Environment specification for Deployment Agent"""
    base_image: str
    packages: List[str]
    services: List[str]
    network_config: Dict[str, Any]
    file_system: Dict[str, Any]
    environment_variables: Dict[str, str]
    ports: List[int]

class ValidationOutput(BaseModel):
    """Output from Validation Agent"""
    result: ValidationResult
    execution_logs: List[str]
    artifacts: Dict[str, Any]  # screenshots, files, etc.
    response_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    execution_time: float
    confidence: float = Field(ge=0.0, le=1.0)

class CVSSVector(BaseModel):
    """CVSS 3.1 Vector representation"""
    attack_vector: str  # N/A/L/P
    attack_complexity: str  # L/H
    privileges_required: str  # N/L/H
    user_interaction: str  # N/R
    scope: str  # U/C
    confidentiality: str  # N/L/H
    integrity: str  # N/L/H
    availability: str  # N/L/H

class CVSSScore(BaseModel):
    """CVSS Score calculation result"""
    vector: CVSSVector
    base_score: float = Field(ge=0.0, le=10.0)
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    justification: Dict[str, str]  # Explanation for each metric

class TriageResult(BaseModel):
    """Final triage result"""
    report_id: str
    raw_report: RawReport
    analysis_metadata: AnalysisMetadata
    environment_spec: EnvironmentSpec
    validation_output: ValidationOutput
    cvss_score: CVSSScore
    processing_time: float
    timestamp: datetime
    status: str  # "completed", "failed", "requires_review"
    human_review_required: bool = False
    notes: Optional[str] = None

class AgentResponse(BaseModel):
    """Standard response format for all agents"""
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    execution_time: float
    metadata: Optional[Dict[str, Any]] = None

class PipelineState(BaseModel):
    """State tracking for the pipeline"""
    report_id: str
    current_stage: str
    completed_stages: List[str]
    failed_stages: List[str]
    start_time: datetime
    last_update: datetime
    error_count: int = 0
    retry_count: int = 0
