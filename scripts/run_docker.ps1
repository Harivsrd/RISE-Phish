Write-Host "=== RISE-Phish Container Orchestration ===" -ForegroundColor Cyan
Write-Host "Building and launching containers via Docker Compose..." -ForegroundColor Yellow

docker compose up --build -d

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nRISE-Phish services launched successfully!" -ForegroundColor Green
    Write-Host "Dashboard UI: http://localhost:3000" -ForegroundColor White
    Write-Host "FastAPI Docs: http://localhost:8000/docs" -ForegroundColor White
    Write-Host "Health Check: http://localhost:8000/api/v1/health" -ForegroundColor White
    Write-Host "`nTo view live logs: docker compose logs -f" -ForegroundColor Gray
    Write-Host "To stop services:  docker compose down" -ForegroundColor Gray
} else {
    Write-Host "`nDocker Compose failed with exit code $LASTEXITCODE." -ForegroundColor Red
}
