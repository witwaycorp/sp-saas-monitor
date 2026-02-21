# install.ps1 - Run as Administrator on target machine
# All files are in the same folder as this script

param(
    [string]$InstallPath = "C:\Program Files\SaaSMonitor",
    [switch]$Uninstall
)

# Get the directory where this script is located
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

function Install-SaaSMonitor {
    Write-Host "Installing SaaS Monitor..." -ForegroundColor Green
    Write-Host "Script location: $scriptPath" -ForegroundColor Cyan
    Write-Host "All files will be copied from this folder" -ForegroundColor Cyan
    
    # Create installation directories
    Write-Host "Creating installation directories..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path "$InstallPath\bin" -Force | Out-Null
    New-Item -ItemType Directory -Path "$InstallPath\logs" -Force | Out-Null
    New-Item -ItemType Directory -Path "$InstallPath\config" -Force | Out-Null
    
    # Check if executable exists in the same folder
    $exeSource = "$scriptPath\sp-saas-monitor.exe"
    if (Test-Path $exeSource) {
        Write-Host "✅ Found executable at: $exeSource" -ForegroundColor Green
        Copy-Item $exeSource "$InstallPath\bin\" -Force
    } else {
        Write-Host "❌ ERROR: Could not find sp-saas-monitor.exe in $scriptPath" -ForegroundColor Red
        Write-Host "   Please make sure the executable is in the same folder as this script" -ForegroundColor Yellow
        exit 1
    }
    
    # Check for config file
    $configSource = "$scriptPath\config.yaml"
    if (Test-Path $configSource) {
        Write-Host "✅ Found config at: $configSource" -ForegroundColor Green
        Copy-Item $configSource "$InstallPath\config\" -Force
    } else {
        Write-Host "⚠️  No config file found, creating default config..." -ForegroundColor Yellow
        # Create default config
        @"
saas_apps:
  - name: "Salesforce"
    domains:
      - "salesforce.com"
      - "force.com"
      - "login.salesforce.com"
      - "sfdcstatic.com"
  
  - name: "Microsoft 365"
    domains:
      - "microsoft.com"
      - "microsoftonline.com"
      - "office.com"
      - "teams.microsoft.com"
      - "github.com"
      - "githubcopilot.com"

monitoring:
  interface: null
  capture_dns: true
  capture_tls_sni: true
  process_cache_seconds: 60

logging:
  log_file: "$InstallPath\\logs\\saas-monitor.log"
  log_level: "info"
  alert_on_detection: true
"@ | Out-File -FilePath "$InstallPath\config\config.yaml" -Encoding utf8
    }
    
    # Set permissions on logs directory
    Write-Host "Setting permissions on logs directory..." -ForegroundColor Yellow
    $logsPath = "$InstallPath\logs"
    icacls $logsPath /grant "NETWORK SERVICE:(OI)(CI)F" /T
    icacls $logsPath /grant "LOCAL SERVICE:(OI)(CI)F" /T
    
    # Install Windows service
    Write-Host "Installing Windows service..." -ForegroundColor Yellow
    $serviceName = "SaaSProxyMonitor"
    $binaryPath = "$InstallPath\bin\sp-saas-monitor.exe"
    
    # Stop and remove existing service if present
    if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
        Write-Host "Removing existing service..." -ForegroundColor Yellow
        Stop-Service $serviceName -Force
        sc.exe delete $serviceName
        Start-Sleep -Seconds 2
    }
    
    # Create new service
    New-Service -Name $serviceName `
        -BinaryPathName "`"$binaryPath`"" `
        -DisplayName "SaaS Proxy Monitor" `
        -Description "Monitors network traffic for SaaS application detection" `
        -StartupType Automatic
    
    # Set recovery options
    sc.exe failure $serviceName reset=86400 actions=restart/5000/restart/10000/restart/30000
    
    # Start the service
    Write-Host "Starting service..." -ForegroundColor Yellow
    Start-Service $serviceName
    
    Write-Host "`n✅ Installation complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Service installed as: $serviceName" -ForegroundColor Cyan
    Write-Host "Installation path: $InstallPath" -ForegroundColor Cyan
    Write-Host "Logs location: $InstallPath\logs\saas-monitor.log" -ForegroundColor Cyan
    Write-Host "Config location: $InstallPath\config\config.yaml" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To check service status:" -ForegroundColor White
    Write-Host "  Get-Service $serviceName" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To view logs:" -ForegroundColor White
    Write-Host "  Get-Content '$InstallPath\logs\saas-monitor.log' -Wait" -ForegroundColor Gray
}

function Uninstall-SaaSMonitor {
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
}

# Main execution
Write-Host "SaaS Monitor Installer" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host "Current folder: $scriptPath" -ForegroundColor Gray
Write-Host ""

if ($Uninstall) {
    Uninstall-SaaSMonitor
} else {
    Install-SaaSMonitor
}