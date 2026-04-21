"""
INTENTIONAL VULNERABILITIES FOR SECURITY TESTING
WARNING: Never use these patterns in production!
"""

# VULNERABILITY 1: Hardcoded API Keys
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABILITY 2: Hardcoded Database Credentials
DATABASE_PASSWORD = "super_secret_password_123"
DB_CONNECTION_STRING = "postgresql://admin:password123@localhost:5432/production_db"

# VULNERABILITY 3: Hardcoded API Tokens
STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

# VULNERABILITY 4: Insecure Configuration
DEBUG = True
SECRET_KEY = "django-insecure-hardcoded-secret-key-12345"
ALLOWED_HOSTS = ['*']

def get_api_key():
    """Returns hardcoded API key - INSECURE!"""
    return "sk_test_BQokikJOvBiI2HlWgH4olfQ2"