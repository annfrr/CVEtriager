"""
Test script for the CVE Triage Framework
"""
import asyncio
import json
import os
from main_pipeline import CVETriagePipeline
from utils.models import RawReport

async def test_framework():
    """Test the framework with a simple report"""
    
    # Create a simple test report
    test_report = RawReport(
        title="Test XSS Vulnerability",
        description="A simple reflected XSS vulnerability for testing",
        steps_to_reproduce="1. Navigate to the test page\n2. Enter <script>alert('test')</script>\n3. Submit the form",
        payload="<script>alert('test')</script>",
        affected_url="https://httpbin.org/get",
        affected_software="Test Application",
        software_version="1.0.0"
    )
    
    print("Testing CVE Triage Framework...")
    print(f"Report Title: {test_report.title}")
    print("-" * 50)
    
    # Initialize pipeline
    pipeline = CVETriagePipeline()
    
    try:
        # Process the report
        result = await pipeline.process_report(test_report)
        
        print(f"\nResults:")
        print(f"Report ID: {result.report_id}")
        print(f"Status: {result.status}")
        print(f"Processing Time: {result.processing_time:.2f} seconds")
        print(f"Human Review Required: {result.human_review_required}")
        
        if result.analysis_metadata:
            print(f"\nAnalysis:")
            print(f"Vulnerability Type: {result.analysis_metadata.vulnerability_type}")
            print(f"Confidence Score: {result.analysis_metadata.confidence_score}")
            print(f"Affected Components: {', '.join(result.analysis_metadata.affected_components)}")
        
        if result.validation_output:
            print(f"\nValidation:")
            print(f"Result: {result.validation_output.result}")
            print(f"Confidence: {result.validation_output.confidence}")
            print(f"Execution Time: {result.validation_output.execution_time:.2f} seconds")
        
        if result.cvss_score:
            print(f"\nCVSS Scoring:")
            print(f"Base Score: {result.cvss_score.base_score}")
            severity = pipeline.scoring_agent.get_severity_level(result.cvss_score.base_score)
            print(f"Severity Level: {severity}")
            print(f"CVSS Vector: {result.cvss_score.vector.dict()}")
        
        if result.notes:
            print(f"\nNotes: {result.notes}")
        
        print("\n✅ Framework test completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Framework test failed: {str(e)}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        pipeline.cleanup_all_pipelines()

if __name__ == "__main__":
    # Check if OpenAI API key is set
    if not os.getenv("OPENAI_API_KEY"):
        print("❌ OPENAI_API_KEY environment variable not set!")
        print("Please set your OpenAI API key:")
        print("export OPENAI_API_KEY=your_api_key_here")
        exit(1)
    
    asyncio.run(test_framework())
