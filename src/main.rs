mod config;
mod process_monitor;
mod saas_detector;
mod logging;
mod dns_resolver;

use crate::config::Config;
use crate::process_monitor::{ProcessMonitor, TcpConnection};
use crate::saas_detector::SaaSDetector;
use crate::logging::setup_logging;
use crate::dns_resolver::DnsResolver;
use log::{info, error, warn, debug};
use std::path::Path;
use std::sync::Arc;
use std::collections::HashSet;
use tokio::sync::mpsc;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode,
        ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use std::time::Duration;

define_windows_service!(ffi_service_main, service_main);

fn service_main(arguments: Vec<std::ffi::OsString>) {
    // Initialize logging
    if let Err(e) = setup_logging(false) {  // false = quiet mode for service
        eprintln!("Failed to setup logging: {}", e);
    }
    
    if let Err(e) = run_service(arguments) {
        error!("Service failed: {}", e);
    }
}

fn run_service(_arguments: Vec<std::ffi::OsString>) -> Result<(), Box<dyn std::error::Error>> {
    info!("SaaS Proxy Monitor service starting...");
    
    // Create a channel to handle service control events
    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();
    
    // Define service control handler
    let status_handle = service_control_handler::register(
        "SaaSProxyMonitor",
        move |control_event| {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    info!("Received stop/shutdown signal");
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => {
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        },
    )?;

    // Report service is running
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    info!("SaaS Proxy Monitor service started successfully");

    // Load configuration - check multiple locations
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    
    let config_path = if exe_dir.join("config.yaml").exists() {
        exe_dir.join("config.yaml")
    } else if Path::new("config.yaml").exists() {
        Path::new("config.yaml").to_path_buf()
    } else if Path::new("C:\\ProgramData\\SaaSMonitor\\config.yaml").exists() {
        Path::new("C:\\ProgramData\\SaaSMonitor\\config.yaml").to_path_buf()
    } else {
        Path::new("config.yaml").to_path_buf() // Will fail, use defaults
    };

    info!("Loading config from: {:?}", config_path);

    let config = if config_path.exists() {
        match Config::load(&config_path) {
            Ok(cfg) => {
                info!("Configuration loaded from {}", config_path.display());
                info!("Config has {} SaaS apps configured", cfg.saas_apps.len());
                Arc::new(cfg)
            }
            Err(e) => {
                warn!("Failed to load config ({}), using defaults", e);
                Arc::new(Config::default())
            }
        }
    } else {
        warn!("Config not found at {}, using defaults", config_path.display());
        Arc::new(Config::default())
    };

    // Create runtime with a larger stack size
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(3 * 1024 * 1024) // 3MB stack
        .enable_all()
        .build()?;
    
    // Use runtime.block_on - this returns the value from the async block
    let block_result: Result<(), Box<dyn std::error::Error>> = runtime.block_on(async {
        // Create channels for TCP connection events (larger capacity to handle bursts)
        let (conn_tx, mut conn_rx) = mpsc::channel::<TcpConnection>(1000);

        // Initialize components
        let process_monitor = Arc::new(ProcessMonitor::with_connection_sender(
            config.monitoring.process_cache_seconds,
            conn_tx,
        ));

        // Initialize DNS resolver for IP-to-domain resolution (5 min cache)
        let dns_resolver = Arc::new(DnsResolver::new(300));

        // Log initial process list for debugging
        info!("Getting initial process list...");
        let processes = process_monitor.get_all_processes().await;
        info!("Found {} running processes", processes.len());

        let detector: Arc<SaaSDetector> = Arc::new(SaaSDetector::new(config.clone()));

        // Create shutdown channel
        let (poller_shutdown_tx, mut poller_shutdown_rx) = mpsc::channel::<()>(1);

        // Spawn TCP poller task - polls TCP table every 500ms for ALL sessions
        let poller_handle = tokio::spawn(async move {
            info!("TCP connection poller started (cross-session monitoring)");
            let mut interval = tokio::time::interval(Duration::from_millis(500));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Poll TCP table - this sees connections from ALL sessions
                        let _ = process_monitor.poll_tcp_connections().await;
                    }
                    _ = poller_shutdown_rx.recv() => {
                        info!("TCP poller shutting down gracefully");
                        break;
                    }
                }
            }
        });

        // Track seen connections to avoid redundant processing
        // Key: (remote_ip, remote_port, local_port, pid) - unique connection identifier
        let mut seen_connections: HashSet<(std::net::Ipv4Addr, u16, u16, u32)> = HashSet::new();
        const MAX_SEEN_CONNECTIONS: usize = 10000;

        // Main event loop - process TCP connection events
        info!("Main event loop started - monitoring connections from all sessions");
        loop {
            tokio::select! {
                Some(conn) = conn_rx.recv() => {
                    // Skip connections to private/local IPs
                    if conn.remote_addr.is_private() || conn.remote_addr.is_loopback() {
                        continue;
                    }

                    // Only check established connections
                    if conn.state.0 != 5 { // ESTAB=5
                        continue;
                    }

                    // Create unique key for this connection
                    let conn_key = (conn.remote_addr, conn.remote_port, conn.local_port, conn.pid);

                    // Skip if we've already processed this connection
                    if seen_connections.contains(&conn_key) {
                        continue;
                    }

                    // Add to seen set
                    seen_connections.insert(conn_key);

                    // Prune seen set if it gets too large (prevent memory bloat)
                    if seen_connections.len() > MAX_SEEN_CONNECTIONS {
                        // Remove oldest 50% of entries
                        seen_connections.drain().take(MAX_SEEN_CONNECTIONS / 2).count();
                    }

                    debug!("New connection: {}:{} -> {}:{} (PID: {}, Process: {})",
                        conn.local_addr, conn.local_port,
                        conn.remote_addr, conn.remote_port,
                        conn.pid,
                        conn.process_name.as_deref().unwrap_or("unknown"));

                    // Create connection event for detection
                    let event = crate::saas_detector::ConnectionEvent {
                        source_ip: std::net::IpAddr::V4(conn.local_addr),
                        source_port: conn.local_port,
                        dest_ip: std::net::IpAddr::V4(conn.remote_addr),
                        dest_port: conn.remote_port,
                        protocol: crate::saas_detector::Protocol::TCP,
                        domain_hint: None,
                        timestamp: chrono::Local::now(),
                    };

                    // Use background DNS resolution (non-blocking, updates cache)
                    let resolved_domain = dns_resolver.resolve_background(event.dest_ip).await;

                    // Log connection details for troubleshooting
                    debug!("Checking connection: {}:{} -> {}:{} (PID: {}, Process: {}, DNS: {:?})",
                        conn.local_addr, conn.local_port,
                        conn.remote_addr, conn.remote_port,
                        conn.pid,
                        conn.process_name.as_deref().unwrap_or("unknown"),
                        resolved_domain);

                    // Detect SaaS traffic (checks domain first, then IP ranges)
                    if let Some(detection) = detector.detect(&event, resolved_domain.as_deref()) {
                        // Log detection to file
                        info!("DETECTED: {} - {}:{} -> {}:{} (pattern: {}, process: {})",
                            detection.app_name,
                            event.source_ip, event.source_port,
                            event.dest_ip, event.dest_port,
                            detection.matched_pattern,
                            conn.process_name.as_deref().unwrap_or("unknown"));

                        // Also print to console
                        println!("\n🔍 SaaS DETECTED: {} - {} (PID: {})",
                            detection.app_name,
                            detection.matched_pattern,
                            conn.process_name.as_deref().unwrap_or("unknown"));
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received, stopping...");
                    // Send shutdown signal to poller
                    let _ = poller_shutdown_tx.send(()).await;
                    // Wait for poller to finish
                    match tokio::time::timeout(Duration::from_secs(5), poller_handle).await {
                        Ok(Ok(_)) => info!("TCP poller stopped gracefully"),
                        Ok(Err(e)) => warn!("TCP poller task error: {}", e),
                        Err(_) => {
                            warn!("TCP poller did not stop within timeout, aborting");
                        }
                    }
                    break;
                }
            }
        }

        Ok(())
    });
    
    // Handle the result from the async block
    if let Err(e) = block_result {
        error!("Error in main loop: {}", e);
    }

    // Report service stopped
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    info!("SaaS Proxy Monitor service stopped");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check if we're running as a service or console app
    if std::env::args().any(|arg| arg == "--console") {
        // Run in console mode for testing
        println!("🚀 SaaS Monitor running in CONSOLE mode");
        println!("========================================");
        println!("📡 Monitoring connections from ALL sessions");
        println!("🔍 Detecting MCP agent traffic to SaaS domains");

        // Setup logging - true = verbose console output
        setup_logging(true)?;

        // Create runtime with larger stack
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_stack_size(3 * 1024 * 1024) // 3MB stack
            .enable_all()
            .build()?;

        let console_result: Result<(), Box<dyn std::error::Error>> = runtime.block_on(async {
            // Load config from same directory as executable
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
            
            let config_path = if exe_dir.join("config.yaml").exists() {
                exe_dir.join("config.yaml")
            } else if Path::new("config.yaml").exists() {
                Path::new("config.yaml").to_path_buf()
            } else {
                Path::new("C:\\ProgramData\\SaaSMonitor\\config.yaml").to_path_buf()
            };

            info!("Console mode loading config from: {:?}", config_path);
            
            let config = if config_path.exists() {
                match Config::load(&config_path) {
                    Ok(cfg) => {
                        info!("Configuration loaded from {}", config_path.display());
                        cfg
                    }
                    Err(e) => {
                        warn!("Failed to load config ({}), using defaults", e);
                        Config::default()
                    }
                }
            } else {
                warn!("Config not found at {}, using defaults", config_path.display());
                Config::default()
            };
            
            let config = Arc::new(config);
            let detector = SaaSDetector::new(config.clone());
            let dns_resolver = Arc::new(DnsResolver::new(300));

            // Create channel for TCP connections (larger capacity)
            let (conn_tx, mut conn_rx) = mpsc::channel::<TcpConnection>(1000);
            let monitor = Arc::new(ProcessMonitor::with_connection_sender(60, conn_tx));

            // Show some running processes
            println!("\n📋 Current running processes:");
            let processes = monitor.get_all_processes().await;
            for proc in processes.iter().take(10) {
                println!("   PID: {:6} - {}", proc.pid, proc.name);
            }
            println!("   ... and {} more", processes.len().saturating_sub(10));

            println!("\n🔄 Starting connection monitor...");
            println!("   Press Ctrl+C to stop\n");
            println!("   Only SaaS detections will be shown below");
            println!("   Full logs: C:\\ProgramData\\SaaSMonitor\\logs\\saas-monitor.log\n");

            // Spawn TCP poller task - 500ms for faster detection
            let poller_handle = tokio::spawn(async move {
                info!("TCP connection poller started (cross-session monitoring)");
                let mut interval = tokio::time::interval(Duration::from_millis(500));

                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let _ = monitor.poll_tcp_connections().await;
                        }
                        _ = tokio::signal::ctrl_c() => {
                            break;
                        }
                    }
                }
            });

            // Track seen connections to avoid redundant processing
            let mut seen_connections: HashSet<(std::net::Ipv4Addr, u16, u16, u32)> = HashSet::new();
            const MAX_SEEN_CONNECTIONS: usize = 10000;

            // Process events - only show detections in console
            loop {
                tokio::select! {
                    Some(conn) = conn_rx.recv() => {
                        // Skip connections to private/local IPs
                        if conn.remote_addr.is_private() || conn.remote_addr.is_loopback() {
                            continue;
                        }

                        // Only check established connections
                        if conn.state.0 != 5 { // ESTAB=5
                            continue;
                        }

                        // Create unique key for this connection
                        let conn_key = (conn.remote_addr, conn.remote_port, conn.local_port, conn.pid);

                        // Skip if we've already processed this connection
                        if seen_connections.contains(&conn_key) {
                            continue;
                        }

                        // Add to seen set
                        seen_connections.insert(conn_key);

                        // Prune seen set if it gets too large
                        if seen_connections.len() > MAX_SEEN_CONNECTIONS {
                            seen_connections.drain().take(MAX_SEEN_CONNECTIONS / 2).count();
                        }

                        // Create ConnectionEvent from TcpConnection
                        let event = crate::saas_detector::ConnectionEvent {
                            source_ip: std::net::IpAddr::V4(conn.local_addr),
                            source_port: conn.local_port,
                            dest_ip: std::net::IpAddr::V4(conn.remote_addr),
                            dest_port: conn.remote_port,
                            protocol: crate::saas_detector::Protocol::TCP,
                            domain_hint: None,
                            timestamp: chrono::Local::now(),
                        };

                        // Use background DNS resolution (non-blocking)
                        let resolved_domain = dns_resolver.resolve_background(event.dest_ip).await;

                        // Detect SaaS traffic
                        if let Some(detection) = detector.detect(&event, resolved_domain.as_deref()) {
                            // This is the only thing that prints to console
                            println!("\n{}", "=".repeat(60));
                            println!("🔍 \x1b[91mSaaS DETECTED\x1b[0m");
                            println!("{}", "=".repeat(60));
                            println!("   App: \x1b[93m{}\x1b[0m", detection.app_name);
                            println!("   Domain: \x1b[92m{}\x1b[0m", detection.matched_pattern);
                            println!("   Connection: {}:{} -> {}:{}",
                                event.source_ip, event.source_port, event.dest_ip, event.dest_port);

                            // Log to file with more details
                            info!("DETECTED: {} - {}:{} -> {}:{} (pattern: {})",
                                detection.app_name,
                                event.source_ip, event.source_port,
                                event.dest_ip, event.dest_port,
                                detection.matched_pattern);

                            // Get process info
                            if let Some(process_name) = &conn.process_name {
                                println!("   Process: \x1b[92m{} (PID:{})\x1b[0m", process_name, conn.pid);
                                info!("   Process: {} (PID:{}) - {}", 
                                    process_name, conn.pid, 
                                    conn.process_path.as_deref().unwrap_or("unknown"));

                                // Check if this is a browser process
                                let process_lower = process_name.to_lowercase();
                                if process_lower.contains("chrome") ||
                                   process_lower.contains("edge") ||
                                   process_lower.contains("firefox") ||
                                   process_lower.contains("opera") ||
                                   process_lower.contains("brave") ||
                                   process_lower.contains("msedge") {
                                    println!("   Browser: \x1b[94m✓ Yes (expected)\x1b[0m");
                                } else {
                                    println!("   Browser: \x1b[91m⚠️ Non-browser process!\x1b[0m");
                                }
                            } else {
                                println!("   Process: \x1b[90m<unknown>\x1b[0m");
                                info!("   No process found for port {}", event.source_port);
                            }
                            println!("   Time: {}", chrono::Local::now().format("%H:%M:%S"));
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        println!("\n\n👋 Shutting down...");
                        info!("Shutdown signal received");
                        poller_handle.abort();
                        break;
                    }
                }
            }

            Ok(())
        });

        if let Err(e) = console_result {
            error!("Console mode error: {}", e);
        }
    } else {
        // Run as Windows service
        service_dispatcher::start("SaaSProxyMonitor", ffi_service_main)?;
    }

    Ok(())
}