"""
Example script to run a single vulnerability report through the pipeline
"""
import asyncio
import json
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from main_pipeline import CVETriagePipeline
from utils.models import RawReport

async def run_report_from_file(report_file: str):
    """Run a vulnerability report from JSON file"""
    
    # Load report from file
    with open(report_file, 'r') as f:
        report_data = json.load(f)
    
    # Create RawReport object
    report = RawReport(**report_data)
    
    # Initialize pipeline
    pipeline = CVETriagePipeline()
    
    print(f"Processing report: {report.title}")
    print(f"Description: {report.description}")
    print("-" * 50)
    
    try:
        # Process report
        result = await pipeline.process_report(report)
        
        # Print results
        print(f"\nTRIAGE RESULTS:")
        print(f"Report ID: {result.report_id}")
        print(f"Status: {result.status}")
        print(f"Processing Time: {result.processing_time:.2f} seconds")
        print(f"Human Review Required: {result.human_review_required}")
        
        if result.analysis_metadata:
            print(f"\nANALYSIS:")
            print(f"Vulnerability Type: {result.analysis_metadata.vulnerability_type}")
            print(f"Confidence Score: {result.analysis_metadata.confidence_score}")
            print(f"Affected Components: {', '.join(result.analysis_metadata.affected_components)}")
        
        if result.validation_output:
            print(f"\nVALIDATION:")
            print(f"Result: {result.validation_output.result}")
            print(f"Confidence: {result.validation_output.confidence}")
            print(f"Execution Time: {result.validation_output.execution_time:.2f} seconds")
        
        if result.cvss_score:
            print(f"\nCVSS SCORING:")
            print(f"Base Score: {result.cvss_score.base_score}")
            severity = pipeline.scoring_agent.get_severity_level(result.cvss_score.base_score)
            print(f"Severity Level: {severity}")
            print(f"CVSS Vector: {result.cvss_score.vector.dict()}")
            
            # Generate severity report
            severity_report = pipeline.scoring_agent.generate_severity_report(
                result.cvss_score, result.analysis_metadata
            )
            print(f"\nRECOMMENDATIONS:")
            for rec in severity_report['recommendations']:
                print(f"- {rec}")
        
        if result.notes:
            print(f"\nNOTES: {result.notes}")
            
    except Exception as e:
        print(f"Error processing report: {str(e)}")
    
    finally:
        # Cleanup
        pipeline.cleanup_all_pipelines()

async def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python run_single_report.py <report_file.json>")
        print("Example: python run_single_report.py ../reports/sql_injection_report.json")
        sys.exit(1)
    
    report_file = sys.argv[1]
    
    if not os.path.exists(report_file):
        print(f"Report file not found: {report_file}")
        sys.exit(1)
    
    await run_report_from_file(report_file)

if __name__ == "__main__":
    asyncio.run(main())
