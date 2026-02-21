# SaaS Monitor - MCP Agent Traffic Detector

A Windows service that monitors network connections **across all sessions** to detect MCP (Model Context Protocol) agents using stolen tokens to communicate with SaaS applications like Salesforce, Microsoft 365, Google Workspace, and more.

## Key Features

- **Cross-Session Monitoring**: Detects connections from ALL user sessions, not just the current one
- **Process Identification**: Identifies which process initiated each connection
- **Domain Detection**: Matches connections against known SaaS domains and IP ranges
- **Reverse DNS Lookup**: Resolves IP addresses to domain names for detection
- **Non-Browser Alerting**: Highlights suspicious non-browser processes connecting to SaaS apps
- **Windows Service**: Runs as a background service with automatic startup

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    TCP Table Poller                         │
│              (GetExtendedTcpTable - ALL sessions)           │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   DNS Resolver                              │
│              (Reverse DNS lookup with cache)                │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   SaaS Detector                             │
│         (Domain pattern + IP range matching)                │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   Alert Engine                              │
│    (Log to file + Console output for non-browser apps)      │
└─────────────────────────────────────────────────────────────┘
```

## Why This Works for Cross-Session Detection

The key insight is that `GetExtendedTcpTable` (Windows IP Helper API) returns the **system-wide TCP connection table**, which includes connections from:
- All user sessions (logged in users, RDP sessions, service sessions)
- All processes regardless of session ID
- Both inbound and outbound connections

This is different from packet capture (Npcap/WinPcap) which:
- Only sees packets on network interfaces
- May miss loopback traffic
- Requires promiscuous mode for cross-session visibility
- Doesn't directly provide process IDs

### Important: ICMP (ping) Limitation

**This tool monitors TCP connections only.** The `ping` command uses **ICMP** (Internet Control Message Protocol), which:
- Does not use TCP or UDP ports
- Creates no entry in the TCP connection table
- Cannot be attributed to a specific process via the TCP table

**To test detection**, use TCP-based tools instead:
```powershell
# Good - uses TCP
curl https://login.salesforce.com
Invoke-WebRequest https://salesforce.com

# Not detected - uses ICMP
ping salesforce.com
```

For ICMP monitoring, you would need packet capture (Npcap) or Windows Filtering Platform (WFP) callouts, which are more complex and have their own limitations.

## Deployment Instructions

### Prerequisites

1. **Windows 10/11 or Windows Server 2016+**
2. **Administrator privileges** (required for service installation and TCP table access)
3. **Rust toolchain** (for building from source)
   ```powershell
   # Install Rust from https://rustup.rs or using winget:
   winget install Rustlang.Rustup
   ```
4. **NO additional dependencies** (Npcap is NOT required!)

### Installation

#### Option A: Pre-built Binary (Recommended)

1. **Download the latest release** from GitHub Releases
2. **Extract to deployment location**:
   ```
   C:\ProgramData\SaaSMonitor\
   ├── bin\sp-saas-monitor.exe
   ├── config\config.yaml
   ├── install.ps1
   ├── uninstall.ps1
   └── check-prereqs.ps1
   ```
3. **Install the service** (run PowerShell as Administrator):
   ```powershell
   cd C:\ProgramData\SaaSMonitor
   .\install.ps1
   ```
4. **Verify installation**:
   ```powershell
   Get-Service SaaSProxyMonitor
   ```

#### Option B: Build from Source

1. **Build the project**:
   ```powershell
   cd C:\path\to\sp-saas-monitor
   cargo build --release
   ```

2. **Create deployment structure**:
   ```powershell
   New-Item -ItemType Directory -Force -Path "C:\ProgramData\SaaSMonitor\bin"
   Copy-Item ".\target\release\sp-saas-monitor.exe" "C:\ProgramData\SaaSMonitor\bin\"
   Copy-Item ".\config.yaml" "C:\ProgramData\SaaSMonitor\config.yaml"
   Copy-Item ".\install.ps1", ".\uninstall.ps1", ".\check-prereqs.ps1" "C:\ProgramData\SaaSMonitor\"
   ```

3. **Install the service** (run PowerShell as Administrator):
   ```powershell
   cd C:\ProgramData\SaaSMonitor
   .\install.ps1
   ```

### Running in Console Mode (for testing)

```powershell
& "C:\ProgramData\SaaSMonitor\bin\sp-saas-monitor.exe" --console
```

## Configuration

Edit `config.yaml` to customize detection patterns:

```yaml
saas_apps:
  - name: "Salesforce"
    domains:
      - "salesforce.com"
      - "force.com"
      - "login.salesforce.com"
    ip_ranges:
      - "13.111.0.0/16"
      - "136.146.0.0/16"
```

### Supported SaaS Applications (default config)

| Application | Detection Method |
|------------|------------------|
| Salesforce | Domain + IP ranges |
| Microsoft 365 | Domain + IP ranges |
| Google Workspace | Domain + IP ranges |
| AWS Console | Domain + IP ranges |
| GitHub | Domain + IP ranges |
| Slack | Domain + IP ranges |
| Zoom | Domain + IP ranges |
| Dropbox | Domain + IP ranges |
| Atlassian | Domain + IP ranges |
| ServiceNow | Domain + IP ranges |
| Workday | Domain + IP ranges |
| Okta | Domain + IP ranges |

## Detection Output

### Console Output
```
============================================================
🔍 SaaS DETECTED
============================================================
   App: Salesforce
   Domain: salesforce.com
   Connection: 192.168.1.100:54321 -> 13.111.22.33:443
   Process: chrome.exe (PID:12345)
   Browser: ✓ Yes (expected)
   Time: 14:32:15
```

### Log File
Location: `C:\ProgramData\SaaSMonitor\logs\saas-monitor.log`

```
2024-01-15 14:32:15 - INFO - DETECTED: Salesforce - 192.168.1.100:54321 -> 13.111.22.33:443 (pattern: salesforce.com, process: chrome.exe)
```

## Troubleshooting

# Stop the Windows service
     - sc stop SaaSProxyMonitor
     # Or kill all instances
     - taskkill /F /IM sp-saas-monitor.exe

### No detections showing

1. **Check if service is running**:
   ```powershell
   Get-Service SaaSProxyMonitor
   ```

2. **View logs**:
   ```powershell
   Get-Content "C:\ProgramData\SaaSMonitor\logs\saas-monitor.log" -Tail 50
   ```

3. **Test with known traffic**:
   ```powershell
   # Open browser and navigate to salesforce.com
   # Or use curl to test
   curl https://login.salesforce.com
   ```

4. **Run in console mode for debugging**:
   ```powershell
   & "C:\ProgramData\SaaSMonitor\bin\sp-saas-monitor.exe" --console
   ```

### High CPU usage

The TCP table poller runs every 2 seconds by default. To reduce frequency, edit `config.yaml`:

```yaml
monitoring:
  poll_interval_seconds: 5  # Increase interval
```

### Missing process names

Some system processes may not have readable names. This is expected behavior.

## Security Considerations

1. **Run as Administrator**: Required for accessing the TCP connection table
2. **Log file protection**: Ensure `C:\ProgramData\SaaSMonitor\logs` has restricted access
3. **Config file integrity**: Protect `config.yaml` from unauthorized modification

## MCP Agent Detection Strategy

This tool detects MCP agents by monitoring for:

1. **Non-browser processes** connecting to SaaS domains (suspicious)
2. **Unknown executables** making authenticated connections
3. **Script hosts** (powershell.exe, python.exe, node.exe) connecting to SaaS apps
4. **Connections from unusual source ports** or patterns

### Indicators of Compromise (IoCs)

| Process Type | SaaS Connection | Risk Level |
|-------------|-----------------|------------|
| Browser | Any SaaS | Low (expected) |
| Office app | SharePoint/OneDrive | Low (expected) |
| Script host | Any SaaS | Medium |
| Unknown exe | Login pages | High |
| Known malware | Any SaaS | Critical |

## Building from Source

```powershell
# Clone repository
git clone https://github.com/your-org/sp-saas-monitor.git
cd sp-saas-monitor

# Build release (NO feature flags needed - pcap is NOT required!)
cargo build --release

# Run in console mode for testing
.\target\release\sp-saas-monitor.exe --console
```

### Build Commands Quick Reference

| Command | Purpose |
|---------|---------|
| `cargo build --release` | Build optimized release binary |
| `cargo build` | Build debug binary (faster, for development) |
| `.\target\release\sp-saas-monitor.exe --console` | Run in console mode |
| `cargo run --release -- --console` | Build and run in one step |

**Note:** Unlike previous versions, **NO feature flags are required**. The `--features pcap` flag is NOT needed because this version uses the Windows IP Helper API instead of packet capture.

## Uninstall

```powershell
# Stop and remove service
.\uninstall.ps1

# Remove files
Remove-Item -Recurse -Force "C:\ProgramData\SaaSMonitor"
```

## License

MIT License

## Contributing

Contributions welcome! Please submit PRs for:
- Additional SaaS domain patterns
- Improved detection algorithms
- Bug fixes and performance improvements

# Restore current working version
## Creates a new branch starting from the tag (safest method)
git checkout -b restore-v1.0.0 v1.0.0

## OR, if you just want to view the code without making changes
git checkout v1.0.0