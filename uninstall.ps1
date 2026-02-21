# uninstall.ps1
# Simple uninstall script

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Uninstalling SaaS Monitor..." -ForegroundColor Yellow

$serviceName = "SaaSProxyMonitor"
$InstallPath = "C:\Program Files\SaaSMonitor"

# Stop and remove service
if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping service..." -ForegroundColor Yellow
    Stop-Service $serviceName -Force
    Write-Host "Removing service..." -ForegroundColor Yellow
    sc.exe delete $serviceName
    Start-Sleep -Seconds 2
    Write-Host "✅ Service removed" -ForegroundColor Green
}

# Remove files
if (Test-Path $InstallPath) {
    Write-Host "Removing files from $InstallPath..." -ForegroundColor Yellow
    Remove-Item -Path $InstallPath -Recurse -Force
    Write-Host "✅ Files removed" -ForegroundColor Green
}

Write-Host "`n✅ Uninstall complete!" -ForegroundColor Green