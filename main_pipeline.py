"""
Main Pipeline for CVE Triage Framework
Orchestrates the four specialized agents to process vulnerability reports
"""
import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional
from agents.analysis_agent import AnalysisAgent
from agents.deployment_agent import DeploymentAgent
from agents.validation_agent import ValidationAgent
from agents.scoring_agent import ScoringAgent
from utils.models import RawReport, TriageResult, PipelineState
from utils.helpers import setup_logging, generate_report_id, log_agent_activity
from config.settings import settings

class CVETriagePipeline:
    """Main pipeline orchestrator for CVE triage"""
    
    def __init__(self):
        self.logger = setup_logging(settings.log_level, settings.log_file)
        self.analysis_agent = AnalysisAgent()
        self.deployment_agent = DeploymentAgent()
        self.validation_agent = ValidationAgent()
        self.scoring_agent = ScoringAgent()
        self.active_pipelines = {}
        
    async def process_report(self, report: RawReport) -> TriageResult:
        """Process vulnerability report through the complete pipeline"""
        report_id = generate_report_id(report.dict())
        start_time = time.time()
        
        # Initialize pipeline state
        pipeline_state = PipelineState(
            report_id=report_id,
            current_stage="analysis",
            completed_stages=[],
            failed_stages=[],
            start_time=datetime.now(),
            last_update=datetime.now()
        )
        
        self.active_pipelines[report_id] = pipeline_state
        
        try:
            self.logger.info(f"Starting triage pipeline for report: {report_id}")
            
            # Stage 1: Analysis
            analysis_result = await self._run_analysis_stage(report, pipeline_state)
            if not analysis_result.success:
                return self._create_failed_result(report, pipeline_state, "Analysis failed")
            
            analysis_metadata = analysis_result.data
            
            # Check if manual review is required
            if analysis_metadata.requires_manual_review:
                return self._create_manual_review_result(report, analysis_metadata, pipeline_state)
            
            # Stage 2: Deployment
            deployment_result = await self._run_deployment_stage(analysis_metadata, pipeline_state)
            if not deployment_result.success:
                return self._create_failed_result(report, pipeline_state, "Deployment failed")
            
            container_id = deployment_result.data["container_id"]
            
            # Stage 3: Validation
            validation_result = await self._run_validation_stage(
                container_id, analysis_metadata, pipeline_state
            )
            if not validation_result.success:
                self.deployment_agent.cleanup_environment(report_id)
                return self._create_failed_result(report, pipeline_state, "Validation failed")
            
            validation_output = validation_result.data
            
            # Stage 4: Scoring
            scoring_result = await self._run_scoring_stage(
                analysis_metadata, validation_output, pipeline_state
            )
            if not scoring_result.success:
                self.deployment_agent.cleanup_environment(report_id)
                return self._create_failed_result(report, pipeline_state, "Scoring failed")
            
            cvss_score = scoring_result.data
            
            # Cleanup environment
            self.deployment_agent.cleanup_environment(report_id)
            
            # Create final result
            processing_time = time.time() - start_time
            result = TriageResult(
                report_id=report_id,
                raw_report=report,
                analysis_metadata=analysis_metadata,
                environment_spec=deployment_result.data["environment_spec"],
                validation_output=validation_output,
                cvss_score=cvss_score,
                processing_time=processing_time,
                timestamp=datetime.now(),
                status="completed",
                human_review_required=False
            )
            
            pipeline_state.completed_stages.append("scoring")
            pipeline_state.current_stage = "completed"
            pipeline_state.last_update = datetime.now()
            
            self.logger.info(f"Pipeline completed successfully for report: {report_id}")
            return result
            
        except Exception as e:
            self.logger.error(f"Pipeline failed for report {report_id}: {str(e)}")
            self.deployment_agent.cleanup_environment(report_id)
            return self._create_failed_result(report, pipeline_state, f"Pipeline error: {str(e)}")
        
        finally:
            # Clean up pipeline state
            if report_id in self.active_pipelines:
                del self.active_pipelines[report_id]
    
    async def _run_analysis_stage(self, report: RawReport, 
                                pipeline_state: PipelineState) -> Any:
        """Run analysis stage"""
        self.logger.info(f"Running analysis stage for {pipeline_state.report_id}")
        pipeline_state.current_stage = "analysis"
        
        result = self.analysis_agent.analyze_report(report)
        
        if result.success:
            pipeline_state.completed_stages.append("analysis")
            log_agent_activity("pipeline", "analysis_complete", {
                "report_id": pipeline_state.report_id,
                "vulnerability_type": result.data.vulnerability_type
            })
        else:
            pipeline_state.failed_stages.append("analysis")
            pipeline_state.error_count += 1
        
        return result
    
    async def _run_deployment_stage(self, metadata: Any, 
                                  pipeline_state: PipelineState) -> Any:
        """Run deployment stage"""
        self.logger.info(f"Running deployment stage for {pipeline_state.report_id}")
        pipeline_state.current_stage = "deployment"
        
        result = self.deployment_agent.deploy_environment(
            metadata, pipeline_state.report_id
        )
        
        if result.success:
            pipeline_state.completed_stages.append("deployment")
            log_agent_activity("pipeline", "deployment_complete", {
                "report_id": pipeline_state.report_id,
                "container_id": result.data["container_id"]
            })
        else:
            pipeline_state.failed_stages.append("deployment")
            pipeline_state.error_count += 1
        
        return result
    
    async def _run_validation_stage(self, container_id: str, metadata: Any, 
                                  pipeline_state: PipelineState) -> Any:
        """Run validation stage"""
        self.logger.info(f"Running validation stage for {pipeline_state.report_id}")
        pipeline_state.current_stage = "validation"
        
        result = self.validation_agent.validate_vulnerability(
            container_id, metadata, pipeline_state.report_id
        )
        
        if result.success:
            pipeline_state.completed_stages.append("validation")
            log_agent_activity("pipeline", "validation_complete", {
                "report_id": pipeline_state.report_id,
                "result": result.data.result
            })
        else:
            pipeline_state.failed_stages.append("validation")
            pipeline_state.error_count += 1
        
        return result
    
    async def _run_scoring_stage(self, metadata: Any, validation_output: Any, 
                               pipeline_state: PipelineState) -> Any:
        """Run scoring stage"""
        self.logger.info(f"Running scoring stage for {pipeline_state.report_id}")
        pipeline_state.current_stage = "scoring"
        
        result = self.scoring_agent.calculate_cvss_score(metadata, validation_output)
        
        if result.success:
            pipeline_state.completed_stages.append("scoring")
            log_agent_activity("pipeline", "scoring_complete", {
                "report_id": pipeline_state.report_id,
                "base_score": result.data.base_score
            })
        else:
            pipeline_state.failed_stages.append("scoring")
            pipeline_state.error_count += 1
        
        return result
    
    def _create_failed_result(self, report: RawReport, pipeline_state: PipelineState, 
                            error_message: str) -> TriageResult:
        """Create failed result"""
        processing_time = (datetime.now() - pipeline_state.start_time).total_seconds()
        
        return TriageResult(
            report_id=pipeline_state.report_id,
            raw_report=report,
            analysis_metadata=None,
            environment_spec=None,
            validation_output=None,
            cvss_score=None,
            processing_time=processing_time,
            timestamp=datetime.now(),
            status="failed",
            human_review_required=True,
            notes=error_message
        )
    
    def _create_manual_review_result(self, report: RawReport, metadata: Any, 
                                   pipeline_state: PipelineState) -> TriageResult:
        """Create manual review result"""
        processing_time = (datetime.now() - pipeline_state.start_time).total_seconds()
        
        return TriageResult(
            report_id=pipeline_state.report_id,
            raw_report=report,
            analysis_metadata=metadata,
            environment_spec=None,
            validation_output=None,
            cvss_score=None,
            processing_time=processing_time,
            timestamp=datetime.now(),
            status="requires_review",
            human_review_required=True,
            notes="Manual review required due to low confidence or ambiguous analysis"
        )
    
    def get_pipeline_status(self, report_id: str) -> Optional[PipelineState]:
        """Get current pipeline status"""
        return self.active_pipelines.get(report_id)
    
    def get_all_pipeline_statuses(self) -> Dict[str, PipelineState]:
        """Get all active pipeline statuses"""
        return self.active_pipelines.copy()
    
    def cleanup_all_pipelines(self):
        """Cleanup all active pipelines and environments"""
        for report_id in list(self.active_pipelines.keys()):
            self.deployment_agent.cleanup_environment(report_id)
        self.active_pipelines.clear()

# Example usage
async def main():
    """Example usage of the CVE Triage Pipeline"""
    pipeline = CVETriagePipeline()
    
    # Example report
    report = RawReport(
        title="SQL Injection in Login Form",
        description="The login form is vulnerable to SQL injection attacks",
        steps_to_reproduce="1. Navigate to login page\n2. Enter ' OR 1=1-- in username field\n3. Submit form",
        payload="' OR 1=1--",
        affected_url="https://example.com/login",
        affected_software="Custom Web Application",
        software_version="1.0"
    )
    
    # Process report
    result = await pipeline.process_report(report)
    
    # Print results
    print(f"Report ID: {result.report_id}")
    print(f"Status: {result.status}")
    print(f"Processing Time: {result.processing_time:.2f} seconds")
    
    if result.cvss_score:
        print(f"CVSS Score: {result.cvss_score.base_score}")
        print(f"Severity: {pipeline.scoring_agent.get_severity_level(result.cvss_score.base_score)}")

if __name__ == "__main__":
    asyncio.run(main())
