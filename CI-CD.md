# CI/CD Pipeline Documentation

## Overview

This project uses GitHub Actions for continuous integration and security scanning.

## Pipeline Workflow

The pipeline runs on every push and pull request to the `main` branch.

### Jobs

1. **Build and Test**
   - Sets up Python environment
   - Installs dependencies
   - Runs Django tests
   - Checks deployment readiness

2. **SAST Scan (Bandit)**
   - Static Application Security Testing
   - Scans Python code for security issues
   - Detects: SQL injection, hardcoded passwords, insecure functions
   - Generates: `bandit-report.json`

3. **Dependency Scan (Safety)**
   - Software Composition Analysis
   - Checks for vulnerable dependencies
   - Detects: Known CVEs in packages
   - Generates: `safety-report.json`

4. **Secret Scan (TruffleHog)**
   - Scans for exposed secrets
   - Checks entire git history
   - Detects: API keys, tokens, passwords

5. **Docker Security (Trivy)**
   - Container vulnerability scanning
   - Scans Docker image layers
   - Detects: OS vulnerabilities, dependency issues
   - Generates: `trivy-report.json`

6. **Security Summary**
   - Aggregates all scan results
   - Downloads all reports
   - Provides summary output

## Viewing Results

### GitHub Actions UI
1. Go to repository → Actions tab
2. Click on the latest workflow run
3. View job results and logs

### Download Reports
1. Click on workflow run
2. Scroll to "Artifacts" section
3. Download JSON reports:
   - `bandit-security-report`
   - `safety-dependency-report`
   - `trivy-container-report`

## Expected Vulnerabilities

The pipeline SHOULD detect these intentional vulnerabilities:

### SAST (Bandit)
-  SQL Injection in `tasks/web_views.py`
-  Hardcoded secrets in `tasks/vulnerabilities.py`

### SCA (Safety)
- Vulnerable `requests` package

### Secret Scanning (TruffleHog)
-  AWS keys in `tasks/vulnerabilities.py`
-  Stripe keys in `tasks/vulnerabilities.py`

### Container Scanning (Trivy)
-  OS-level vulnerabilities
-  Python package vulnerabilities

## Security Gates

Currently: `continue-on-error: true` (for demonstration)

For production: Remove this to fail pipeline on vulnerabilities.

## Local Testing

Run security scans locally:

```bash
# SAST
pip install bandit
bandit -r tasks/ securetask/

# Dependency Scan
pip install safety
safety check

# Container Scan
docker build -t securetask:local .
trivy image securetask:local
```

## Notes

- All scans run in parallel after build succeeds
- Reports are stored as artifacts (downloadable)
- Pipeline demonstrates defense-in-depth
- Multiple tool types catch different vulnerability classes