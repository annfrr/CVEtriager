"""
Demo script for the CVE Triage Framework
Shows the framework structure and processes a sample report
"""
import json
import sys
from utils.models import RawReport, VulnerabilityType
from utils.cvss_calculator import CVSSCalculator

def demo_framework():
    """Demonstrate the CVE Triage Framework"""
    
    print("🛡️  CVE Triage Framework Demo")
    print("=" * 50)
    
    # Load a sample report
    print("\n📋 Loading Sample Vulnerability Report...")
    with open('reports/sql_injection_report.json', 'r') as f:
        report_data = json.load(f)
    
    # Create RawReport object
    report = RawReport(**report_data)
    
    print(f"Title: {report.title}")
    print(f"Description: {report.description}")
    print(f"Affected URL: {report.affected_url}")
    print(f"Payload: {report.payload}")
    
    # Simulate Analysis Agent
    print("\n�� Analysis Agent Simulation...")
    print("✅ Report parsed successfully")
    print("✅ Vulnerability type identified: SQL Injection")
    print("✅ Affected components extracted")
    print("✅ Reproduction steps validated")
    print("✅ Confidence score: 0.95")
    
    # Simulate Deployment Agent
    print("\n🐳 Deployment Agent Simulation...")
    print("✅ Docker container created")
    print("✅ Ubuntu 22.04 base image loaded")
    print("✅ Required packages installed: curl, sqlmap, python3")
    print("✅ Environment ready for testing")
    
    # Simulate Validation Agent
    print("\n🔍 Validation Agent Simulation...")
    print("✅ PoC execution started")
    print("✅ SQL injection payload tested")
    print("✅ Authentication bypass confirmed")
    print("✅ Validation result: SUCCESS")
    print("✅ Confidence: 0.90")
    
    # Simulate Scoring Agent
    print("\n📊 Scoring Agent Simulation...")
    cvss_calc = CVSSCalculator()
    
    # Create a sample CVSS vector for SQL injection
    from utils.models import CVSSVector
    sample_vector = CVSSVector(
        attack_vector="N",  # Network
        attack_complexity="L",  # Low
        privileges_required="N",  # None
        user_interaction="N",  # None
        scope="U",  # Unchanged
        confidentiality="H",  # High
        integrity="H",  # High
        availability="H"  # High
    )
    
    cvss_score = cvss_calc.calculate_score(sample_vector)
    
    print(f"✅ CVSS Vector: {sample_vector.dict()}")
    print(f"✅ Base Score: {cvss_score.base_score}")
    print(f"✅ Severity Level: {get_severity_level(cvss_score.base_score)}")
    
    # Final Results
    print("\n🎯 Final Triage Results:")
    print("=" * 30)
    print(f"Report ID: {hash(report.title) % 10000:04d}")
    print(f"Status: COMPLETED")
    print(f"Vulnerability Type: SQL Injection")
    print(f"CVSS Score: {cvss_score.base_score}")
    print(f"Severity: {get_severity_level(cvss_score.base_score)}")
    print(f"Processing Time: ~4.5 minutes")
    print(f"Human Review Required: No")
    
    print("\n✅ CVE Triage Framework Demo Completed Successfully!")
    print("\n📚 This demonstrates the four-agent pipeline:")
    print("   1. Analysis Agent - Interprets vulnerability reports")
    print("   2. Deployment Agent - Sets up testing environments")
    print("   3. Validation Agent - Executes proof-of-concepts")
    print("   4. Scoring Agent - Calculates CVSS scores")

def get_severity_level(score):
    """Get severity level from CVSS score"""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >= 0.1:
        return "Low"
    else:
        return "None"

if __name__ == "__main__":
    demo_framework()
