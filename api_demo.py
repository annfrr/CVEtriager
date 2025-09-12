"""
API Demo for the CVE Triage Framework
Shows how the REST API would work
"""
import json
from utils.models import RawReport, VulnerabilityType
from utils.cvss_calculator import CVSSCalculator

def simulate_api_request():
    """Simulate API request processing"""
    
    print("🌐 CVE Triage Framework API Demo")
    print("=" * 50)
    
    # Simulate API request payload
    api_request = {
        "title": "Remote Code Execution via File Upload",
        "description": "The application allows unrestricted file uploads which can lead to remote code execution",
        "steps_to_reproduce": "1. Navigate to upload page\n2. Upload a PHP file with malicious code\n3. Access the uploaded file\n4. Code executes on server",
        "payload": "<?php system($_GET['cmd']); ?>",
        "affected_url": "https://vulnerable-app.com/upload.php",
        "affected_software": "Custom Web Application",
        "software_version": "2.0.1"
    }
    
    print("📥 API Request Received:")
    print(json.dumps(api_request, indent=2))
    print()
    
    # Process the request
    print("🔄 Processing through pipeline...")
    
    # Simulate Analysis Agent
    print("  🤖 Analysis Agent: Extracting metadata...")
    vulnerability_type = "File Upload"
    confidence = 0.95
    
    # Simulate Deployment Agent  
    print("  🐳 Deployment Agent: Setting up environment...")
    container_id = "cve-triage-12345"
    
    # Simulate Validation Agent
    print("  🔍 Validation Agent: Executing PoC...")
    validation_result = "SUCCESS"
    
    # Simulate Scoring Agent
    print("  📊 Scoring Agent: Calculating CVSS score...")
    cvss_calc = CVSSCalculator()
    
    # Create CVSS vector for file upload vulnerability
    from utils.models import CVSSVector
    cvss_vector = CVSSVector(
        attack_vector="N",  # Network
        attack_complexity="L",  # Low
        privileges_required="N",  # None
        user_interaction="R",  # Required
        scope="U",  # Unchanged
        confidentiality="H",  # High
        integrity="H",  # High
        availability="H"  # High
    )
    
    cvss_score = cvss_calc.calculate_score(cvss_vector)
    
    # Prepare API response
    api_response = {
        "report_id": "12345",
        "status": "completed",
        "processing_time": 4.2,
        "human_review_required": False,
        "vulnerability_type": vulnerability_type,
        "cvss_score": cvss_score.base_score,
        "severity_level": get_severity_level(cvss_score.base_score),
        "cvss_vector": cvss_vector.model_dump(),
        "analysis_metadata": {
            "confidence_score": confidence,
            "affected_components": [api_request["affected_url"]],
            "reproduction_steps": api_request["steps_to_reproduce"].split("\n")
        },
        "validation_output": {
            "result": validation_result,
            "confidence": 0.90,
            "execution_time": 2.1
        },
        "recommendations": [
            "Implement file type validation",
            "Use virus scanning",
            "Store uploaded files outside web root",
            "Implement access controls"
        ]
    }
    
    print("📤 API Response:")
    print(json.dumps(api_response, indent=2))
    
    print(f"\n✅ API Demo completed successfully!")
    print(f"📊 Final Results:")
    print(f"   Report ID: {api_response['report_id']}")
    print(f"   Status: {api_response['status']}")
    print(f"   CVSS Score: {api_response['cvss_score']}")
    print(f"   Severity: {api_response['severity_level']}")
    print(f"   Processing Time: {api_response['processing_time']}s")

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
    simulate_api_request()
