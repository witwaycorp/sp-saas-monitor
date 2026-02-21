# check-prereqs.ps1
# All files are in the same folder as this script

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "🔍 Checking prerequisites for SaaS Monitor..." -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Current folder: $scriptPath" -ForegroundColor Gray
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "✅ Running as Administrator" -ForegroundColor Green
} else {
    Write-Host "❌ NOT running as Administrator - Please run PowerShell as Administrator" -ForegroundColor Red
    exit 1
}

# Check Windows version
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
Write-Host "✅ Windows Version: $($osInfo.Caption)" -ForegroundColor Green

# Check if Npcap is installed
$npcap = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*Npcap*"}
if ($npcap) {
    Write-Host "✅ Npcap is installed" -ForegroundColor Green
} else {
    Write-Host "❌ Npcap is NOT installed - Download from https://npcap.com" -ForegroundColor Red
    Write-Host "   IMPORTANT: Install with 'WinPcap API-compatible Mode' checked" -ForegroundColor Yellow
}

# Check if wpcap.dll exists
if (Test-Path "C:\Windows\System32\wpcap.dll") {
    Write-Host "✅ wpcap.dll found" -ForegroundColor Green
} else {
    Write-Host "❌ wpcap.dll not found - Npcap may not be installed correctly" -ForegroundColor Red
}

# Check available disk space
$drive = Get-PSDrive -Name C
$freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
Write-Host "✅ Free disk space: ${freeSpaceGB}GB" -ForegroundColor Green

# Check if executable exists in current folder
$exePath = "$scriptPath\sp-saas-monitor.exe"
if (Test-Path $exePath) {
    Write-Host "✅ Executable found: $exePath" -ForegroundColor Green
} else {
    Write-Host "❌ Executable NOT found at: $exePath" -ForegroundColor Red
    Write-Host "   Please make sure sp-saas-monitor.exe is in this folder" -ForegroundColor Yellow
}

# Check if config exists
$configPath = "$scriptPath\config.yaml"
if (Test-Path $configPath) {
    Write-Host "✅ Config file found: $configPath" -ForegroundColor Green
} else {
    Write-Host "⚠️  No config file found - default will be created during install" -ForegroundColor Yellow
}

Write-Host "`n📋 Next steps:" -ForegroundColor Cyan
Write-Host "1. Run .\install.ps1 to install the service" -ForegroundColor White
Write-Host "2. Check logs at: C:\Program Files\SaaSMonitor\logs\saas-monitor.log" -ForegroundColor White
Write-Host "3. Test with: ping salesforce.com" -ForegroundColor White