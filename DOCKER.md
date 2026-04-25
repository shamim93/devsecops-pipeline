# Docker Setup Guide

## Prerequisites
- Docker
- Docker Compose

## Quick Start

### 1. Build and Start
```bash
docker compose up -d
```

### 2. Create Superuser
```bash
docker compose exec web python manage.py createsuperuser
```

### 3. Access Application
- Web Interface: http://localhost:8000
- Admin Panel: http://localhost:8000/admin

## Common Commands

### Start Services
```bash
docker compose up -d
```

### Stop Services
```bash
docker compose down
```

### View Logs
```bash
docker compose logs -f
```

### Rebuild After Code Changes
```bash
docker compose down
docker compose build
docker compose up -d
```

### Reset Database (Fresh Start)
```bash
docker compose down -v
docker compose up -d
docker compose exec web python manage.py createsuperuser
```

### Run Django Commands
```bash
# Migrations
docker compose exec web python manage.py migrate
docker compose exec web python manage.py makemigrations

# Shell
docker compose exec web python manage.py shell

# Tests
docker compose exec web python manage.py test
```

### Access Database
```bash
docker compose exec db psql -U securetask_user -d securetask_db
```

## Troubleshooting

### Port Already in Use
If port 8000 is busy, change in docker-compose.yml:
```yaml
ports:
  - "9000:8000"  # Use 9000 instead
```

### Database Connection Issues
```bash
# Check if database is ready
docker compose exec db pg_isready -U securetask_user

# Restart database
docker compose restart db
```

### View Container Status
```bash
docker compose ps
```

## Development vs Production

**Current setup is for DEVELOPMENT only!**

For production:
- Use production-grade WSGI server (gunicorn)
- Set DEBUG=False
- Use strong SECRET_KEY
- Configure proper ALLOWED_HOSTS
- Use environment variables for secrets
- Set up proper volume backups
