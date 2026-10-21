"""Deployment & Containerization Test Suite (Phase 21).

Validates:
1. Dockerfile.backend structural compliance and dependency installation.
2. Dockerfile.frontend multi-stage build and Nginx static runner.
3. frontend/nginx.conf reverse proxy rules, security headers, and SPA routing.
4. docker-compose.yml YAML syntax, service definitions, ports, and volumes.
5. .dockerignore completeness and safety exclusions.
6. Deployment automation scripts (run_docker.sh, run_docker.ps1).
"""
from pathlib import Path
import yaml
import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_dockerfile_backend_configuration():
    """Verify Dockerfile.backend follows production multi-stage and dependency rules."""
    dockerfile_path = REPO_ROOT / "Dockerfile.backend"
    assert dockerfile_path.exists(), "Dockerfile.backend must exist at repository root"

    content = dockerfile_path.read_text(encoding="utf-8")

    # Base image check
    assert "FROM python:3.12" in content
    # System package dependencies
    assert "tesseract-ocr" in content
    assert "playwright install --with-deps chromium" in content
    # Directory setup for volumes
    assert "mkdir -p /app/data /app/temp/screenshots" in content
    # Port & Healthcheck
    assert "EXPOSE 8000" in content
    assert "HEALTHCHECK" in content
    assert "http://localhost:8000/api/v1/health" in content
    # Uvicorn entrypoint
    assert "uvicorn" in content
    assert "backend.app.main:app" in content


def test_dockerfile_frontend_configuration():
    """Verify Dockerfile.frontend uses multi-stage build with Nginx runner."""
    dockerfile_path = REPO_ROOT / "Dockerfile.frontend"
    assert dockerfile_path.exists(), "Dockerfile.frontend must exist at repository root"

    content = dockerfile_path.read_text(encoding="utf-8")

    # Multi-stage definition
    assert "FROM node:20-alpine AS builder" in content
    assert "npm run build" in content
    assert "FROM nginx:alpine AS runner" in content
    # Static files copy
    assert "COPY --from=builder /app/dist /usr/share/nginx/html" in content
    # Port & Healthcheck
    assert "EXPOSE 80" in content
    assert "HEALTHCHECK" in content
    assert "nginx" in content


def test_nginx_configuration():
    """Verify Nginx reverse-proxy routes /api/ to FastAPI and provides SPA routing."""
    nginx_conf_path = REPO_ROOT / "frontend" / "nginx.conf"
    assert nginx_conf_path.exists(), "frontend/nginx.conf must exist"

    content = nginx_conf_path.read_text(encoding="utf-8")

    # SPA routing
    assert "try_files $uri $uri/ /index.html;" in content
    # Reverse proxy to backend
    assert "location /api/ {" in content
    assert "proxy_pass http://backend:8000/api/;" in content
    # Security headers
    assert "X-Frame-Options" in content
    assert "X-Content-Type-Options" in content
    # Container health probe
    assert "location /health {" in content


def test_docker_compose_syntax_and_topology():
    """Verify docker-compose.yml parses cleanly and defines backend and frontend services."""
    compose_path = REPO_ROOT / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist at repository root"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    assert "services" in compose_data
    services = compose_data["services"]

    # 1. Backend Service
    assert "backend" in services
    backend = services["backend"]
    assert "8000:8000" in backend["ports"]
    assert "healthcheck" in backend
    assert backend["restart"] == "unless-stopped"

    # Verify volumes
    assert "volumes" in compose_data
    assert "rise_phish_data" in compose_data["volumes"]
    assert "rise_phish_screenshots" in compose_data["volumes"]

    # 2. Frontend Service
    assert "frontend" in services
    frontend = services["frontend"]
    assert any("3000" in p for p in frontend["ports"])
    assert "backend" in frontend.get("depends_on", {})


def test_dockerignore_rules():
    """Verify .dockerignore prevents sensitive or build-heavy files from entering images."""
    dockerignore_path = REPO_ROOT / ".dockerignore"
    assert dockerignore_path.exists(), ".dockerignore must exist"

    content = dockerignore_path.read_text(encoding="utf-8")
    assert ".git" in content
    assert ".venv" in content
    assert "node_modules" in content
    assert "dist" in content
    assert "rise_phish.db" in content


def test_deployment_scripts():
    """Verify deployment helper scripts exist and contain docker compose commands."""
    sh_script = REPO_ROOT / "scripts" / "run_docker.sh"
    ps_script = REPO_ROOT / "scripts" / "run_docker.ps1"

    assert sh_script.exists(), "scripts/run_docker.sh must exist"
    assert ps_script.exists(), "scripts/run_docker.ps1 must exist"

    sh_content = sh_script.read_text(encoding="utf-8")
    assert "docker compose up --build" in sh_content

    ps_content = ps_script.read_text(encoding="utf-8")
    assert "docker compose up --build" in ps_content
