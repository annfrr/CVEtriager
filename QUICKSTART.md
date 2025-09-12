# Quick Start Guide

## 🚀 Get Started in 5 Minutes

### 1. Prerequisites
- Python 3.8+
- Docker installed
- OpenAI API key

### 2. Setup
```bash
# Clone and navigate to the project
cd cve_triage_framework

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env and add your OpenAI API key
```

### 3. Test the Framework
```bash
# Set your OpenAI API key
export OPENAI_API_KEY=your_api_key_here

# Run a simple test
python test_framework.py
```

### 4. Process a Vulnerability Report
```bash
# Process a single report
python examples/run_single_report.py reports/sql_injection_report.json

# Process all reports
python examples/run_batch_reports.py reports/
```

### 5. Start the API Server
```bash
# Start the REST API
python api_server.py

# Test the API
curl -X POST "http://localhost:8000/triage" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test XSS",
    "description": "Reflected XSS vulnerability",
    "steps_to_reproduce": "1. Navigate to page\n2. Enter <script>alert(1)</script>\n3. Submit",
    "payload": "<script>alert(1)</script>",
    "affected_url": "https://httpbin.org/get"
  }'
```

### 6. Using Docker (Recommended)
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f cve-triage

# Stop services
docker-compose down
```

## 📊 Expected Results

After processing a report, you should see:
- **Analysis**: Vulnerability type identification
- **Deployment**: Environment setup in Docker container
- **Validation**: PoC execution and validation
- **Scoring**: CVSS score and severity assessment

## 🔧 Troubleshooting

### Common Issues:
1. **OpenAI API Key**: Make sure it's set in `.env` file
2. **Docker**: Ensure Docker is running and accessible
3. **Permissions**: Run `sudo usermod -aG docker $USER` if needed

### Debug Mode:
```bash
export LOG_LEVEL=DEBUG
python test_framework.py
```

## 📚 Next Steps

1. Read the full [README.md](README.md) for detailed documentation
2. Explore the [API endpoints](README.md#-api-endpoints)
3. Customize agent configurations in `config/settings.py`
4. Add your own vulnerability reports to `reports/`

## 🆘 Need Help?

- Check the [troubleshooting section](README.md#-troubleshooting)
- Review logs in the `logs/` directory
- Create an issue in the repository

Happy triaging! 🛡️
