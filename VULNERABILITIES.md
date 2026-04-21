# Intentional Vulnerabilities Documentation

**⚠️ WARNING: This application contains intentional security vulnerabilities for educational and testing purposes.**

**DO NOT deploy to production!**

## Purpose
These vulnerabilities are added to:
1. Test security scanning tools (SAST, DAST, SCA)
2. Demonstrate the DevSecOps pipeline's detection capabilities
3. Serve as educational examples of common security issues

## List of Intentional Vulnerabilities

### 1. SQL Injection (High Severity)
**Location:** `tasks/web_views.py` - `search_tasks_vulnerable()`
**Type:** CWE-89
**Description:** Raw SQL query with string formatting allows SQL injection
**Example Attack:** `' OR '1'='1` in search box
**Fix:** Use Django ORM or parameterized queries

### 2. Cross-Site Scripting (XSS) (Medium Severity)
**Location:** `tasks/templates/tasks/search_results.html`
**Type:** CWE-79
**Description:** Unescaped user input using `|safe` filter
**Example Attack:** `<script>alert('XSS')</script>` in search
**Fix:** Remove `|safe` filter, use Django's auto-escaping

### 3. Hardcoded Secrets (Critical Severity)
**Location:** `tasks/vulnerabilities.py`
**Type:** CWE-798
**Description:** API keys, passwords, and tokens hardcoded in source
**Example:** AWS keys, database passwords, API tokens
**Fix:** Use environment variables and secret management

### 4. Missing Authentication (Critical Severity)
**Location:** `tasks/views.py` - `get_all_tasks_insecure()`
**Type:** CWE-306
**Description:** API endpoint exposing all user data without authentication
**URL:** `/api/insecure/all-tasks/`
**Fix:** Add authentication requirement

### 5. Vulnerable Dependencies (Medium Severity)
**Location:** `requirements.txt`
**Type:** CWE-1104
**Description:** Using outdated packages with known CVEs
**Example:** `requests==2.25.1` (multiple CVEs)
**Fix:** Update to latest versions

### 6. Insecure Configuration (Low Severity)
**Location:** `tasks/vulnerabilities.py`
**Type:** CWE-16
**Description:** Debug mode enabled, weak secret keys
**Fix:** Use secure configuration for production

## Testing the Vulnerabilities

### SQL Injection Test:
1. Login to web interface
2. Go to Search page
3. Enter: `' OR '1'='1 --`
4. Should see all tasks (bypassing user filter)

### XSS Test:
1. Search for: `<script>alert('XSS')</script>`
2. Script should execute in browser

### Missing Authentication Test:
```bash
curl http://localhost:8000/api/insecure/all-tasks/
# Should return all tasks without login
```

### Hardcoded Secrets Test:
```bash
# Security tools should detect these in code scan
grep -r "AKIA" tasks/
```

## Security Tools Detection

These vulnerabilities should be detected by:
- **Bandit (SAST):** SQL injection, hardcoded passwords
- **Safety (SCA):** Vulnerable dependencies
- **TruffleHog:** Hardcoded secrets
- **OWASP ZAP (DAST):** XSS, missing authentication
- **Trivy:** Container vulnerabilities

## Remediation

For production deployment, all these vulnerabilities MUST be fixed:
1. Use Django ORM for database queries
2. Never use `|safe` with user input
3. Use environment variables for secrets
4. Require authentication on all sensitive endpoints
5. Keep dependencies updated
6. Use secure configuration settings