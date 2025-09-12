# AI-Agent Framework for Automated CVE Triage

An intelligent, modular framework that automates vulnerability triage using specialized AI agents. This system processes vulnerability reports, validates proof-of-concepts in sandboxed environments, and generates CVSS scores automatically.

## 🚀 Features

- **Modular AI Agents**: Four specialized agents for analysis, deployment, validation, and scoring
- **Automated PoC Validation**: Executes proof-of-concepts in isolated Docker containers
- **CVSS 3.1 Scoring**: Automated severity assessment with detailed justifications
- **REST API**: Complete API for integration with existing security tools
- **Docker Support**: Containerized deployment with Docker Compose
- **Multiple Vulnerability Types**: Supports XSS, SQL Injection, File Upload, Path Traversal, Command Injection, SSRF, and more

## 🏗️ Architecture

The framework consists of four specialized AI agents:

1. **Analysis Agent**: Interprets vulnerability reports using GPT-4
2. **Deployment Agent**: Sets up sandboxed testing environments
3. **Validation Agent**: Executes proof-of-concepts and validates exploits
4. **Scoring Agent**: Calculates CVSS scores and generates severity assessments

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Analysis Agent │ -> │Deployment Agent │ -> │Validation Agent │ -> │ Scoring Agent   │
│                 │    │                 │    │                 │    │                 │
│ • Report Parse  │    │ • Environment   │    │ • PoC Execute   │    │ • CVSS Calc     │
│ • Metadata Extr │    │ • Package Inst  │    │ • Result Valid  │    │ • Severity Ass  │
│ • Confidence    │    │ • Container Mgmt│    │ • Artifact Coll │    │ • Recommendations│
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📋 Prerequisites

- Python 3.8+
- Docker and Docker Compose
- OpenAI API Key
- 4GB+ RAM
- 10GB+ free disk space

## 🛠️ Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd cve_triage_framework
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` file with your configuration:

```env
# OpenAI API Configuration
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4
OPENAI_TEMPERATURE=0.1
OPENAI_MAX_TOKENS=2000

# Docker Configuration
DOCKER_TIMEOUT=300
DOCKER_MEMORY_LIMIT=1g
DOCKER_CPU_LIMIT=1.0

# Pipeline Configuration
CONFIDENCE_THRESHOLD=0.7
POC_TIMEOUT=180
MAX_RETRIES=3

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=logs/triage.log
```

### 4. Create Required Directories

```bash
mkdir -p logs artifacts
```

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f cve-triage

# Stop services
docker-compose down
```

### Option 2: Local Development

```bash
# Start the API server
python api_server.py

# Or run the pipeline directly
python main_pipeline.py
```

## 📖 Usage

### 1. Using the REST API

The API server runs on `http://localhost:8000` by default.

#### Process a Single Report

```bash
curl -X POST "http://localhost:8000/triage" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "SQL Injection in Login Form",
    "description": "The login form is vulnerable to SQL injection attacks",
    "steps_to_reproduce": "1. Navigate to login page\n2. Enter '\'' OR 1=1-- in username field\n3. Submit form",
    "payload": "' OR 1=1--",
    "affected_url": "https://example.com/login",
    "affected_software": "Custom Web Application",
    "software_version": "1.0"
  }'
```

#### Get Triage Results

```bash
curl "http://localhost:8000/triage/{report_id}"
```

#### Get Statistics

```bash
curl "http://localhost:8000/stats"
```

### 2. Using Python Scripts

#### Process a Single Report

```bash
python examples/run_single_report.py reports/sql_injection_report.json
```

#### Process Multiple Reports

```bash
python examples/run_batch_reports.py reports/
```

### 3. Using the Python API

```python
import asyncio
from main_pipeline import CVETriagePipeline
from utils.models import RawReport

async def process_vulnerability():
    pipeline = CVETriagePipeline()
    
    report = RawReport(
        title="XSS in Search Function",
        description="Reflected XSS vulnerability in search functionality",
        steps_to_reproduce="1. Navigate to search page\n2. Enter <script>alert('XSS')</script>\n3. Submit form",
        payload="<script>alert('XSS')</script>",
        affected_url="https://example.com/search"
    )
    
    result = await pipeline.process_report(report)
    
    print(f"Status: {result.status}")
    print(f"CVSS Score: {result.cvss_score.base_score}")
    print(f"Severity: {pipeline.scoring_agent.get_severity_level(result.cvss_score.base_score)}")

asyncio.run(process_vulnerability())
```

## 📊 Test Reports

The `reports/` directory contains sample vulnerability reports for testing:

- `sql_injection_report.json` - SQL injection vulnerability
- `xss_report.json` - Cross-site scripting vulnerability
- `file_upload_report.json` - Unrestricted file upload vulnerability
- `path_traversal_report.json` - Directory traversal vulnerability
- `command_injection_report.json` - Command injection vulnerability
- `ssrf_report.json` - Server-side request forgery vulnerability

## 🔧 Configuration

### Agent Configuration

Each agent can be configured in `config/settings.py`:

```python
AGENT_CONFIGS = {
    "analysis": {
        "model": "gpt-4",
        "temperature": 0.1,
        "max_tokens": 2000
    },
    "deployment": {
        "base_image": "ubuntu:22.04",
        "timeout": 300,
        "memory_limit": "1g"
    },
    "validation": {
        "timeout": 180,
        "max_retries": 3,
        "tools": ["curl", "sqlmap", "nmap", "nikto"]
    },
    "scoring": {
        "cvss_version": "3.1",
        "model": "gpt-4",
        "temperature": 0.0
    }
}
```

### Vulnerability Type Mappings

The framework supports various vulnerability types defined in `config/settings.py`:

- XSS (Cross-Site Scripting)
- SQL Injection
- File Upload
- Path Traversal
- Command Injection
- Authentication Issues
- Authorization Issues
- SSRF (Server-Side Request Forgery)
- File Disclosure

## 📈 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Root endpoint with API information |
| `/health` | GET | Health check endpoint |
| `/triage` | POST | Process a single vulnerability report |
| `/triage/batch` | POST | Process multiple vulnerability reports |
| `/triage/{report_id}` | GET | Get triage result by report ID |
| `/triage/{report_id}/status` | GET | Get pipeline status for a report |
| `/triage` | GET | List all triage results (paginated) |
| `/triage/{report_id}` | DELETE | Delete triage result |
| `/stats` | GET | Get framework statistics |

## 🔍 Monitoring and Logging

### Logs

Logs are stored in the `logs/` directory:

- `triage.log` - Main application logs
- Agent-specific logs for debugging

### Metrics

The framework tracks:

- Processing times per stage
- Success/failure rates
- CVSS score distributions
- Vulnerability type distributions
- Resource usage

## 🛡️ Security Considerations

### Sandboxing

- All PoC executions run in isolated Docker containers
- Containers are automatically cleaned up after processing
- Resource limits prevent resource exhaustion attacks

### Input Validation

- All inputs are sanitized before processing
- Confidence thresholds prevent low-quality reports from being processed
- Manual review flags for ambiguous cases

### API Security

- CORS enabled for cross-origin requests
- Input validation on all endpoints
- Error handling without information disclosure

## 🐛 Troubleshooting

### Common Issues

1. **Docker Permission Denied**
   ```bash
   sudo usermod -aG docker $USER
   # Log out and back in
   ```

2. **OpenAI API Rate Limits**
   - Reduce concurrent requests
   - Implement exponential backoff
   - Check API key validity

3. **Container Resource Issues**
   - Increase Docker memory limits
   - Reduce concurrent processing
   - Check available disk space

4. **Validation Failures**
   - Check network connectivity
   - Verify target URLs are accessible
   - Review validation logs

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
python api_server.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📚 References

- [CVSS 3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Docker Documentation](https://docs.docker.com/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

## 🆘 Support

For support and questions:

- Create an issue in the repository
- Check the troubleshooting section
- Review the logs for error details

## 🔮 Future Enhancements

- [ ] Integration with CVE databases
- [ ] Machine learning model training
- [ ] Advanced exploit detection
- [ ] Multi-language support
- [ ] Web UI dashboard
- [ ] Integration with SIEM systems
- [ ] Automated remediation suggestions
- [ ] Threat intelligence integration

---

**Note**: This framework is designed for educational and research purposes. Always ensure you have proper authorization before testing vulnerabilities on any systems.
