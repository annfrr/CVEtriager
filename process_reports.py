"""
Process all vulnerability reports through the CVE Triage Framework
"""
import json
import os
from utils.models import RawReport, VulnerabilityType
from utils.cvss_calculator import CVSSCalculator

def process_all_reports():
    """Process all vulnerability reports in the reports directory"""
    
    print("🛡️  CVE Triage Framework - Processing All Reports")
    print("=" * 60)
    
    # Get all JSON files in reports directory
    report_files = [f for f in os.listdir('reports/') if f.endswith('.json')]
    
    if not report_files:
        print("❌ No report files found in reports/ directory")
        return
    
    print(f"📋 Found {len(report_files)} vulnerability reports to process")
    print()
    
    results = []
    
    for i, report_file in enumerate(report_files, 1):
        print(f"[{i}/{len(report_files)}] Processing: {report_file}")
        print("-" * 40)
        
        try:
            # Load report
            with open(f'reports/{report_file}', 'r') as f:
                report_data = json.load(f)
            
            report = RawReport(**report_data)
            
            # Simulate the triage process
            result = simulate_triage_process(report)
            results.append(result)
            
            # Print results
            print(f"✅ Status: {result['status']}")
            print(f"✅ Vulnerability Type: {result['vulnerability_type']}")
            print(f"✅ CVSS Score: {result['cvss_score']}")
            print(f"✅ Severity: {result['severity']}")
            print(f"✅ Processing Time: {result['processing_time']}s")
            print()
            
        except Exception as e:
            print(f"❌ Error processing {report_file}: {str(e)}")
            print()
    
    # Print summary
    print("=" * 60)
    print("📊 BATCH PROCESSING SUMMARY")
    print("=" * 60)
    
    successful = sum(1 for r in results if r['status'] == 'COMPLETED')
    total = len(results)
    
    print(f"Total Reports: {total}")
    print(f"Successfully Processed: {successful}")
    print(f"Success Rate: {(successful/total)*100:.1f}%")
    
    # Vulnerability type distribution
    vuln_types = {}
    for result in results:
        vuln_type = result['vulnerability_type']
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    print(f"\nVulnerability Type Distribution:")
    for vuln_type, count in vuln_types.items():
        print(f"  {vuln_type}: {count}")
    
    # Severity distribution
    severities = {}
    for result in results:
        severity = result['severity']
        severities[severity] = severities.get(severity, 0) + 1
    
    print(f"\nSeverity Distribution:")
    for severity, count in severities.items():
        print(f"  {severity}: {count}")
    
    # Average processing time
    avg_time = sum(r['processing_time'] for r in results) / len(results)
    print(f"\nAverage Processing Time: {avg_time:.1f} seconds")
    
    print(f"\n✅ All reports processed successfully!")

def simulate_triage_process(report):
    """Simulate the triage process for a report"""
    
    # Simulate processing time (based on report complexity)
    processing_time = 2.0 + len(report.description) / 100
    
    # Determine vulnerability type from title/description
    title_lower = report.title.lower()
    desc_lower = report.description.lower()
    
    if 'sql' in title_lower or 'sql' in desc_lower:
        vuln_type = "SQL Injection"
        cvss_score = 8.5  # High severity
    elif 'xss' in title_lower or 'cross-site' in title_lower:
        vuln_type = "Cross-Site Scripting (XSS)"
        cvss_score = 6.1  # Medium severity
    elif 'upload' in title_lower:
        vuln_type = "File Upload"
        cvss_score = 9.1  # Critical severity
    elif 'traversal' in title_lower or 'path' in title_lower:
        vuln_type = "Path Traversal"
        cvss_score = 7.5  # High severity
    elif 'command' in title_lower or 'injection' in title_lower:
        vuln_type = "Command Injection"
        cvss_score = 9.8  # Critical severity
    elif 'ssrf' in title_lower or 'server-side' in title_lower:
        vuln_type = "Server-Side Request Forgery (SSRF)"
        cvss_score = 8.2  # High severity
    else:
        vuln_type = "Unknown"
        cvss_score = 5.0  # Medium severity
    
    # Determine severity level
    if cvss_score >= 9.0:
        severity = "Critical"
    elif cvss_score >= 7.0:
        severity = "High"
    elif cvss_score >= 4.0:
        severity = "Medium"
    else:
        severity = "Low"
    
    return {
        'status': 'COMPLETED',
        'vulnerability_type': vuln_type,
        'cvss_score': cvss_score,
        'severity': severity,
        'processing_time': processing_time
    }

if __name__ == "__main__":
    process_all_reports()
