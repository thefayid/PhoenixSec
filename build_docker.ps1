Write-Host "🐳 Building PhoenixSec Docker image..." -ForegroundColor Cyan
docker build -t phoenixsec/scanner:latest .

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ PhoenixSec Docker image built successfully!" -ForegroundColor Green
    Write-Host "Run it using:" -ForegroundColor Yellow
    Write-Host "docker run --rm -v `${PWD}:/workspace phoenixsec/scanner:latest scan ." -ForegroundColor White
} else {
    Write-Host "❌ Failed to build Docker image." -ForegroundColor Red
}
