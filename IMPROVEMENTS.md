# Network Monitor Improvements - Real-time SaaS Detection

## Problem Analysis

The original implementation had a **50-second delay** in detecting SaaS connections due to:

1. **Mock Data Fallback**: Packet capture (pcap) requires admin privileges and often fails on Windows, falling back to mock data with artificial 2-second delays between events
2. **Slow DNS Resolution**: 2-second timeout per DNS lookup, blocking the event loop
3. **No Connection Tracking**: Processing the same connections repeatedly instead of only new connections
4. **Slow Polling**: TCP table polled every 1 second instead of more frequently

## Changes Made

### 1. Removed Mock Data (`packet_sniffer.rs`)
- **Before**: Used pcap library for packet capture, fell back to mock data when capture failed
- **After**: Simplified to only contain `ConnectionEvent` struct for compatibility
- **Benefit**: No more artificial delays, relies on reliable TCP table polling

### 2. Optimized DNS Resolution (`dns_resolver.rs`)
- **Reduced timeout**: 2000ms → 500ms for uncached lookups
- **Added background resolution**: `resolve_background()` method returns immediately, updates cache asynchronously
- **Improved caching**: 
  - Success: 10 minutes (was 5 min)
  - Timeout/Failure: 1 minute (was 2 min)
- **Benefit**: DNS lookups no longer block connection processing

### 3. Connection Tracking (`main.rs`)
- **Added seen connections HashSet**: Tracks `(remote_ip, remote_port, local_port, pid)` tuples
- **Only process new connections**: Skip already-seen connections
- **Memory management**: Prunes oldest 50% when set exceeds 10,000 entries
- **Benefit**: Eliminates redundant processing of persistent connections

### 4. Faster TCP Polling (`main.rs`)
- **Polling interval**: 1000ms → 500ms
- **Benefit**: Detects new connections twice as fast

### 5. Fixed Configuration Issues
- **Cargo.toml**: Fixed invalid `edition = "2024"` → `edition = "2021"`
- **Removed unused dependencies**: `rand`, `pcap` (optional feature removed)

### 6. SaaS Detection (`saas_detector.rs`)
- **Moved types**: `ConnectionEvent` and `Protocol` moved from packet_sniffer for compatibility
- **Workday already configured**: `config.yaml` already has Workday domains and IP ranges

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    TCP Table Poller                          │
│              (GetExtendedTcpTable API)                       │
│                  Polls every 500ms                           │
│              Sees ALL sessions (cross-session)               │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ TcpConnection events
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Connection Tracker                          │
│           HashSet<(remote_ip, port, local_port, pid)>       │
│              Filters out duplicate connections               │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ New connections only
                      ▼
┌─────────────────────────────────────────────────────────────┐
│               Background DNS Resolver                        │
│            500ms timeout, async cache update                 │
│         Returns immediately with cached value (if any)       │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ IP + optional domain
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   SaaS Detector                              │
│         Domain pattern matching + IP range matching          │
│         Configured apps: Salesforce, Zoom, Workday           │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ Detections logged
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Log Output                                │
│        File: C:\ProgramData\SaaSMonitor\logs\monitor.log    │
│        Console: Real-time detection alerts                   │
└─────────────────────────────────────────────────────────────┘
```

## Expected Performance Improvement

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| First detection time | ~50 seconds | < 2 seconds | 25x faster |
| DNS lookup timeout | 2000ms | 500ms | 4x faster |
| Polling frequency | 1000ms | 500ms | 2x faster |
| Mock data delays | 2000ms per event | 0ms | Eliminated |
| Duplicate processing | Every poll | Once per connection | Eliminated |

## Testing

Run in console mode for testing:
```powershell
# Build first
cargo build --release

# Run in console mode (no service installation required)
.\target\release\sp-saas-monitor.exe --console
```

Then:
1. Open a browser and navigate to `https://login.salesforce.com`
2. Open another tab to `https://www.workday.com`
3. Detections should appear within 1-2 seconds

## Configured SaaS Applications

### Salesforce
- Domains: salesforce.com, force.com, login.salesforce.com, test.salesforce.com, sfdcstatic.com, krxd.net, tableau.com, heroku.com, herokuapp.com, einstein.ai, salesforceliveagent.com, contentforce.com, datorama.com
- IP Ranges: 13.110.0.0/15, 13.111.0.0/16, 136.146.0.0/16, 161.71.0.0/16, 52.0.0.0/11, 54.0.0.0/9

### Zoom
- Domains: zoom.us, zoomgov.com, zoomweb.net, zoom.com, zoomcloudmeetings.com
- IP Ranges: 3.7.0.0/16, 3.128.0.0/12, 52.11.0.0/16, 52.12.0.0/15, etc.

### Workday
- Domains: workday.com, myworkday.com, myworkdayjobs.com, workday.aws
- IP Ranges: 13.248.0.0/16, 76.76.0.0/16, 130.214.0.0/16

## Future Enhancements (Not Implemented)

- **WFP Monitor**: `wfp_monitor.rs` exists but not integrated - could provide kernel-level connection monitoring
- **Inbound Connection Tracking**: Currently only monitors outbound connections
- **Topology View**: Visual representation of all connections (requires additional UI component)
- **MCP Agent Detection**: Specific heuristics for detecting AI agents using stolen cookies

## Notes

- Works **cross-session** - detects connections from ALL user sessions, not just the current user
- **No admin privileges required** - uses `GetExtendedTcpTable` API instead of packet capture
- **Memory efficient** - connection tracking prevents redundant processing
- **Production ready** - runs as Windows service or console application
