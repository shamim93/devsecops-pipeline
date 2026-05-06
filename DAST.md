# DAST - Dynamic Application Security Testing

## Overview

DAST (Dynamic Application Security Testing) tests the **running application** for security vulnerabilities by simulating real attacks.

## SAST vs DAST

| Aspect | SAST (Bandit) | DAST (OWASP ZAP) |
|--------|---------------|------------------|
| **Type** | Static analysis | Dynamic testing |
| **When** | During build | During runtime |
| **Analyzes** | Source code | Running application |
| **Detects** | Code-level issues | Runtime vulnerabilities |
| **Examples** | SQL injection patterns, hardcoded secrets | XSS, CSRF, auth bypass |
| **False Positives** | Can be higher | Generally lower |
| **Code Access** | Required | Not required |

## OWASP ZAP Scans

### Baseline Scan
- Quick passive scan
- Analyzes HTTP traffic
- Low false positives
- 2-5 minutes

### Full Scan
- Active scanning + passive
- Attempts exploits
- Comprehensive coverage
- 10-30 minutes

## Vulnerabilities DAST Can Detect

### Will Detect (in our app):
- **XSS** - Cross-Site Scripting in search
- **Missing security headers**
- **CSRF** - Missing CSRF tokens (we disabled in settings)
- **Session issues** - Insecure cookie settings
- **SQL Injection** - Runtime SQL injection

### Won't Detect:
-  Hardcoded secrets (SAST only)
-  Vulnerable dependencies (SCA only)
-  Code quality issues (SAST only)

## Running DAST Locally

### Prerequisites
```bash
docker pull zaproxy/zap-stable
```

### Quick Scan
```bash
# Start application
docker compose up -d

# Run ZAP baseline scan
docker run -t zaproxy/zap-stable zap-baseline.py \
  -t http://host.docker.internal:8000

# Stop application
docker compose down
```

### Full Scan
```bash
docker run -v $(pwd):/zap/wrk/:rw -t zaproxy/zap-stable \
  zap-full-scan.py \
  -t http://host.docker.internal:8000 \
  -r zap-report.html
```

## Expected Findings

Based on our intentional vulnerabilities:

### High Risk
1. **SQL Injection** - In search endpoint
2. **XSS** - In search results (unescaped output)
3. **Missing Authentication** - `/api/insecure/all-tasks/`

### Medium Risk
1. **Missing Security Headers** - CSP, X-Frame-Options
2. **CSRF** - Protection disabled in settings
3. **Session Management** - Cookie security flags

### Low Risk
1. **Information Disclosure** - Debug mode enabled
2. **Timestamp Disclosure**
3. **Directory Listing**

## Integration with CI/CD

DAST runs in separate workflow because:
- Needs running application
- Takes longer (10-30 min)
- Can be scheduled separately
- Useful for staging/pre-production

## Report Analysis

### ZAP Report Sections
1. **Summary** - Issue counts by severity
2. **Alerts** - Detailed vulnerability findings
3. **Site Tree** - Pages scanned
4. **Alerts by Risk** - Prioritized view

### Taking Action
1. Review HIGH and MEDIUM alerts
2. Verify findings (eliminate false positives)
3. Fix code or configuration
4. Re-scan to verify fix
5. Document exceptions if needed

## Security Gates for DAST

Currently: `fail_action: false` (for demonstration)

For production:
```yaml
fail_action: true  # Fail pipeline on HIGH risks
```

## Complementary Scanning

For complete coverage, use ALL tools:
- **SAST** (Bandit) - Code analysis
- **DAST** (ZAP) - Runtime testing
- **SCA** (Safety) - Dependencies
- **Secret Scanning** (TruffleHog) - Credentials
- **Container Scanning** (Trivy) - Images

Each finds different vulnerability types!