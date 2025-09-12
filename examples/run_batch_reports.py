"""
Example script to run multiple vulnerability reports through the pipeline
"""
import asyncio
import json
import sys
import os
from pathlib import Path
from typing import List

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from main_pipeline import CVETriagePipeline
from utils.models import RawReport

async def run_batch_reports(reports_dir: str):
    """Run all reports in a directory"""
    
    # Find all JSON report files
    report_files = []
    for file in os.listdir(reports_dir):
        if file.endswith('.json'):
            report_files.append(os.path.join(reports_dir, file))
    
    if not report_files:
        print(f"No JSON report files found in {reports_dir}")
        return
    
    print(f"Found {len(report_files)} report files")
    print("=" * 60)
    
    # Initialize pipeline
    pipeline = CVETriagePipeline()
    
    results = []
    
    for i, report_file in enumerate(report_files, 1):
        print(f"\n[{i}/{len(report_files)}] Processing: {os.path.basename(report_file)}")
        print("-" * 40)
        
        try:
            # Load report
            with open(report_file, 'r') as f:
                report_data = json.load(f)
            
            report = RawReport(**report_data)
            
            # Process report
            result = await pipeline.process_report(report)
            results.append(result)
            
            # Print summary
            print(f"Status: {result.status}")
            if result.cvss_score:
                severity = pipeline.scoring_agent.get_severity_level(result.cvss_score.base_score)
                print(f"CVSS Score: {result.cvss_score.base_score} ({severity})")
            print(f"Time: {result.processing_time:.2f}s")
            
        except Exception as e:
            print(f"Error: {str(e)}")
            results.append(None)
    
    # Print summary
    print("\n" + "=" * 60)
    print("BATCH PROCESSING SUMMARY")
    print("=" * 60)
    
    successful = sum(1 for r in results if r and r.status == "completed")
    failed = sum(1 for r in results if r and r.status == "failed")
    review_required = sum(1 for r in results if r and r.status == "requires_review")
    
    print(f"Total Reports: {len(report_files)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Requires Review: {review_required}")
    
    # CVSS Score Distribution
    scores = [r.cvss_score.base_score for r in results if r and r.cvss_score]
    if scores:
        print(f"\nCVSS Score Distribution:")
        print(f"Average: {sum(scores)/len(scores):.2f}")
        print(f"Min: {min(scores):.2f}")
        print(f"Max: {max(scores):.2f}")
        
        # Severity distribution
        severity_counts = {}
        for r in results:
            if r and r.cvss_score:
                severity = pipeline.scoring_agent.get_severity_level(r.cvss_score.base_score)
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print(f"\nSeverity Distribution:")
        for severity, count in severity_counts.items():
            print(f"{severity}: {count}")
    
    # Processing time statistics
    times = [r.processing_time for r in results if r]
    if times:
        print(f"\nProcessing Time Statistics:")
        print(f"Average: {sum(times)/len(times):.2f}s")
        print(f"Min: {min(times):.2f}s")
        print(f"Max: {max(times):.2f}s")
    
    # Cleanup
    pipeline.cleanup_all_pipelines()

async def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python run_batch_reports.py <reports_directory>")
        print("Example: python run_batch_reports.py ../reports")
        sys.exit(1)
    
    reports_dir = sys.argv[1]
    
    if not os.path.exists(reports_dir):
        print(f"Reports directory not found: {reports_dir}")
        sys.exit(1)
    
    await run_batch_reports(reports_dir)

if __name__ == "__main__":
    asyncio.run(main())
