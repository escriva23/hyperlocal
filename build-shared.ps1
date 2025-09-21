#!/usr/bin/env pwsh

# PowerShell script to build shared package and install dependencies
Write-Host "Building Hequeendo Shared Package..." -ForegroundColor Green

# Navigate to shared directory and build
Set-Location "shared"
Write-Host "Installing shared dependencies..." -ForegroundColor Yellow
npm install

Write-Host "Building shared package..." -ForegroundColor Yellow
npm run build

if ($LASTEXITCODE -eq 0) {
    Write-Host "Shared package built successfully!" -ForegroundColor Green
} else {
    Write-Host "Failed to build shared package!" -ForegroundColor Red
    exit 1
}

# Navigate to web directory and install dependencies
Set-Location "../web"
Write-Host "Installing web dependencies..." -ForegroundColor Yellow
npm install

if ($LASTEXITCODE -eq 0) {
    Write-Host "Web dependencies installed successfully!" -ForegroundColor Green
} else {
    Write-Host "Failed to install web dependencies!" -ForegroundColor Red
    exit 1
}

# Return to project root
Set-Location ".."

Write-Host "Setup complete! You can now run:" -ForegroundColor Green
Write-Host "   cd web && npm run dev" -ForegroundColor Cyan
Write-Host ""
Write-Host "Don't forget to apply database migrations:" -ForegroundColor Yellow
Write-Host "   supabase db push" -ForegroundColor Cyan
