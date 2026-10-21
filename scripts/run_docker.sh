#!/usr/bin/env bash
set -e

echo "=== RISE-Phish Container Orchestration ==="
echo "Building and launching containers via Docker Compose..."

docker compose up --build -d

echo ""
echo "RISE-Phish services launched successfully!"
echo "Dashboard UI: http://localhost:3000"
echo "FastAPI Docs: http://localhost:8000/docs"
echo "Health Check: http://localhost:8000/api/v1/health"
echo ""
echo "To view live logs: docker compose logs -f"
echo "To stop services:  docker compose down"
