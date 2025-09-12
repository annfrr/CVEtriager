"""
FastAPI server for the CVE Triage Framework
Provides REST API endpoints for vulnerability report processing
"""
import asyncio
import json
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from main_pipeline import CVETriagePipeline
from utils.models import RawReport, TriageResult
from utils.helpers import generate_report_id

# Initialize FastAPI app
app = FastAPI(
    title="CVE Triage Framework API",
    description="AI-Agent Framework for Automated Vulnerability Triage",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global pipeline instance
pipeline = CVETriagePipeline()

# Request/Response models
class VulnerabilityReportRequest(BaseModel):
    title: str
    description: str
    steps_to_reproduce: str
    payload: Optional[str] = None
    affected_url: Optional[str] = None
    affected_software: Optional[str] = None
    software_version: Optional[str] = None
    reporter: Optional[str] = None
    additional_info: Optional[Dict[str, Any]] = None

class TriageResponse(BaseModel):
    report_id: str
    status: str
    processing_time: float
    human_review_required: bool
    cvss_score: Optional[float] = None
    severity_level: Optional[str] = None
    vulnerability_type: Optional[str] = None
    notes: Optional[str] = None

class BatchReportRequest(BaseModel):
    reports: List[VulnerabilityReportRequest]

class PipelineStatusResponse(BaseModel):
    report_id: str
    current_stage: str
    completed_stages: List[str]
    failed_stages: List[str]
    start_time: str
    last_update: str
    error_count: int
    retry_count: int

# In-memory storage for results (in production, use a database)
triage_results: Dict[str, TriageResult] = {}

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "CVE Triage Framework API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "pipeline": "ready"}

@app.post("/triage", response_model=TriageResponse)
async def triage_vulnerability(report: VulnerabilityReportRequest):
    """Process a single vulnerability report"""
    try:
        # Convert to RawReport
        raw_report = RawReport(**report.dict())
        
        # Process through pipeline
        result = await pipeline.process_report(raw_report)
        
        # Store result
        triage_results[result.report_id] = result
        
        # Prepare response
        response = TriageResponse(
            report_id=result.report_id,
            status=result.status,
            processing_time=result.processing_time,
            human_review_required=result.human_review_required,
            notes=result.notes
        )
        
        if result.cvss_score:
            response.cvss_score = result.cvss_score.base_score
            response.severity_level = pipeline.scoring_agent.get_severity_level(
                result.cvss_score.base_score
            )
        
        if result.analysis_metadata:
            response.vulnerability_type = result.analysis_metadata.vulnerability_type
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/triage/batch")
async def triage_batch_reports(request: BatchReportRequest):
    """Process multiple vulnerability reports"""
    try:
        results = []
        
        for report_data in request.reports:
            raw_report = RawReport(**report_data.dict())
            result = await pipeline.process_report(raw_report)
            triage_results[result.report_id] = result
            
            response = TriageResponse(
                report_id=result.report_id,
                status=result.status,
                processing_time=result.processing_time,
                human_review_required=result.human_review_required,
                notes=result.notes
            )
            
            if result.cvss_score:
                response.cvss_score = result.cvss_score.base_score
                response.severity_level = pipeline.scoring_agent.get_severity_level(
                    result.cvss_score.base_score
                )
            
            if result.analysis_metadata:
                response.vulnerability_type = result.analysis_metadata.vulnerability_type
            
            results.append(response)
        
        return {
            "total_reports": len(request.reports),
            "results": results,
            "summary": {
                "successful": sum(1 for r in results if r.status == "completed"),
                "failed": sum(1 for r in results if r.status == "failed"),
                "requires_review": sum(1 for r in results if r.status == "requires_review")
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/triage/{report_id}")
async def get_triage_result(report_id: str):
    """Get triage result by report ID"""
    if report_id not in triage_results:
        raise HTTPException(status_code=404, detail="Report not found")
    
    result = triage_results[report_id]
    
    return {
        "report_id": result.report_id,
        "status": result.status,
        "processing_time": result.processing_time,
        "timestamp": result.timestamp.isoformat(),
        "human_review_required": result.human_review_required,
        "analysis_metadata": result.analysis_metadata.dict() if result.analysis_metadata else None,
        "validation_output": result.validation_output.dict() if result.validation_output else None,
        "cvss_score": result.cvss_score.dict() if result.cvss_score else None,
        "notes": result.notes
    }

@app.get("/triage/{report_id}/status")
async def get_pipeline_status(report_id: str):
    """Get current pipeline status for a report"""
    status = pipeline.get_pipeline_status(report_id)
    
    if not status:
        raise HTTPException(status_code=404, detail="Pipeline status not found")
    
    return PipelineStatusResponse(
        report_id=status.report_id,
        current_stage=status.current_stage,
        completed_stages=status.completed_stages,
        failed_stages=status.failed_stages,
        start_time=status.start_time.isoformat(),
        last_update=status.last_update.isoformat(),
        error_count=status.error_count,
        retry_count=status.retry_count
    )

@app.get("/triage")
async def list_triage_results(limit: int = 10, offset: int = 0):
    """List all triage results"""
    results = list(triage_results.values())
    
    # Apply pagination
    start = offset
    end = offset + limit
    paginated_results = results[start:end]
    
    return {
        "total": len(results),
        "limit": limit,
        "offset": offset,
        "results": [
            {
                "report_id": r.report_id,
                "status": r.status,
                "processing_time": r.processing_time,
                "timestamp": r.timestamp.isoformat(),
                "vulnerability_type": r.analysis_metadata.vulnerability_type if r.analysis_metadata else None,
                "cvss_score": r.cvss_score.base_score if r.cvss_score else None
            }
            for r in paginated_results
        ]
    }

@app.delete("/triage/{report_id}")
async def delete_triage_result(report_id: str):
    """Delete triage result"""
    if report_id not in triage_results:
        raise HTTPException(status_code=404, detail="Report not found")
    
    del triage_results[report_id]
    pipeline.deployment_agent.cleanup_environment(report_id)
    
    return {"message": "Report deleted successfully"}

@app.get("/stats")
async def get_statistics():
    """Get framework statistics"""
    total_reports = len(triage_results)
    
    if total_reports == 0:
        return {
            "total_reports": 0,
            "status_distribution": {},
            "vulnerability_types": {},
            "severity_distribution": {},
            "average_processing_time": 0
        }
    
    # Status distribution
    status_counts = {}
    vuln_type_counts = {}
    severity_counts = {}
    processing_times = []
    
    for result in triage_results.values():
        # Status
        status_counts[result.status] = status_counts.get(result.status, 0) + 1
        
        # Vulnerability types
        if result.analysis_metadata:
            vuln_type = result.analysis_metadata.vulnerability_type
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1
        
        # Severity
        if result.cvss_score:
            severity = pipeline.scoring_agent.get_severity_level(result.cvss_score.base_score)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Processing time
        processing_times.append(result.processing_time)
    
    return {
        "total_reports": total_reports,
        "status_distribution": status_counts,
        "vulnerability_types": vuln_type_counts,
        "severity_distribution": severity_counts,
        "average_processing_time": sum(processing_times) / len(processing_times) if processing_times else 0,
        "min_processing_time": min(processing_times) if processing_times else 0,
        "max_processing_time": max(processing_times) if processing_times else 0
    }

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    pipeline.cleanup_all_pipelines()

if __name__ == "__main__":
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
