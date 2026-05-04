# Security Gates Documentation

## Overview

Security gates are automated checks that **block deployment** if critical security issues are detected.

## Gate Configuration

### Severity Thresholds

| Tool | Threshold | Action |
|------|-----------|--------|
| **Bandit (SAST)** | Medium & High | Fail pipeline |
| **Safety (SCA)** | Critical | Fail pipeline |
| **Trivy (Container)** | High & Critical | Fail pipeline |
| **TruffleHog (Secrets)** | Verified secrets only | Block (currently disabled for demo) |

## Gate Behavior

### When Gates PASS
- All security scans complete
- No issues above threshold
- **Deployment proceeds automatically**

### When Gates FAIL
- Critical/High severity issues detected
- **Pipeline fails**
- **Deployment is BLOCKED**
- Developer must fix issues and re-push

## Bypass Mechanism

### For Educational/Testing Purposes

Current configuration allows some issues for demonstration:
- TruffleHog: `continue-on-error: true` for unverified secrets
- This allows our intentional vulnerabilities to exist

### For Production

To enforce strict gates:
1. Set all `continue-on-error: false`
2. Remove threshold exceptions
3. Require security team approval for bypasses

## Security Gate Workflow
Code Push
↓
Build & Test
↓
Security Scans (Parallel)
├── SAST (Bandit)
├── SCA (Safety)
├── Secrets (TruffleHog)
└── Container (Trivy)
↓
Security Gate Check
↓
├─→ PASS  → Deploy
└─→ FAIL  → Block (Fix required)

## Expected Behavior

### Current Setup (Demo Mode)

With intentional vulnerabilities:
-  Bandit: Will find 9 issues (MEDIUM severity) - **MAY FAIL**
-  Safety: Will find 11 CVEs - **MAY FAIL on critical**
-  Trivy: Will find container issues - **MAY FAIL on HIGH/CRITICAL**

**Result:** Pipeline should FAIL, demonstrating security gates working!

### Production Setup

After removing intentional vulnerabilities:
- All scans pass
- Deployment proceeds
- Only secure code reaches production

## Viewing Gate Results

### In GitHub Actions:
1. Go to Actions tab
2. Click workflow run
3. Failed jobs show  (blocked by security gate)
4. Passed jobs show 

### In Logs:
- Security gate failures show detailed reasons
- Links to fix recommendations
- CVE/CWE references

## Fixing Gate Failures

### SAST Failures (Bandit)
```bash
# View issues
bandit -r tasks/ securetask/ -ll

# Fix SQL injection: Use Django ORM
# Fix secrets: Use environment variables
```

### SCA Failures (Safety)
```bash
# View vulnerable packages
safety check

# Update packages
pip install --upgrade package-name
pip freeze > requirements.txt
```

### Container Failures (Trivy)
```bash
# Scan locally
trivy image securetask:latest

# Update base image
# Update vulnerable packages
```

## Metrics

Track over time:
- Gate failure rate
- Time to fix issues
- Vulnerability trends
- False positive rate