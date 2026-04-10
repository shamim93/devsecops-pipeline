# DevSecOps Pipeline - Secure Task Manager

A Django-based web application demonstrating DevSecOps principles with integrated security testing in CI/CD pipeline.

## Master's Thesis Project
**Topic:** Implementing a Secure DevOps Pipeline with Integrated Security Testing Tools  
**Program:** Master's in Cyber Security

## Project Overview
This project implements a complete DevSecOps pipeline featuring:
- Django web application with intentional vulnerabilities
- Automated security testing (SAST, DAST, SCA)
- Docker containerization
- CI/CD pipeline with GitHub Actions
- Security gates and reporting

## Tech Stack
- **Backend:** Django 4.2, Python 3.9
- **Database:** PostgreSQL 13
- **Containerization:** Docker, Docker Compose
- **CI/CD:** GitHub Actions
- **Security Tools:** Bandit, Safety, Trivy, OWASP ZAP

## Getting Started

### Prerequisites
- Python 3.9
- Docker & Docker Compose
- Git

### Local Development Setup

1. Clone the repository
```bash
git clone git@github.com:shamim93/devsecops-pipeline.git
cd devsecops-pipeline
```

2. Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Run migrations
```bash
python manage.py migrate
```

5. Create superuser
```bash
python manage.py createsuperuser
```

6. Run development server
```bash
python manage.py runserver
```

Visit http://localhost:8000

## Project Status
🚧 **In Development** - Week 3: Building Django Application

## Author
Shamim Hossen - Master's Student in Cyber Security

## License
MIT License - Educational Project
