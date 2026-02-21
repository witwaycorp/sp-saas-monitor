use crate::config::Config;
use std::sync::Arc;
use log::{info, debug, warn};
use std::net::IpAddr;

/// Connection event for SaaS detection
/// Moved from packet_sniffer.rs (now deprecated)
#[derive(Debug, Clone)]
pub struct ConnectionEvent {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
    pub protocol: Protocol,
    pub domain_hint: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Local>,
}

/// Protocol type for network connections
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone)]
pub struct SaaSDetection {
    pub app_name: String,
    pub confidence: DetectionConfidence,
    pub source: DetectionSource,
    pub matched_pattern: String,
    pub event: ConnectionEvent,
}

#[derive(Debug, Clone, Copy)]
pub enum DetectionConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy)]
pub enum DetectionSource {
    DomainName,
    IPAddress,
    SNI,
    DNS,
}

// Ensure SaaSDetector is Send and Sync
unsafe impl Send for SaaSDetector {}
unsafe impl Sync for SaaSDetector {}

pub struct SaaSDetector {
    config: Arc<Config>,
    domain_map: Vec<(String, String)>,
    ip_ranges: Vec<(ipnetwork::Ipv4Network, String)>,
}

impl SaaSDetector {
    pub fn new(config: Arc<Config>) -> Self {
        let mut domain_map = Vec::new();
        let mut ip_ranges = Vec::new();

        for app in &config.saas_apps {
            // Add domain patterns
            for domain in &app.domains {
                domain_map.push((domain.clone(), app.name.clone()));
                debug!("[SaaSDetector] Added domain pattern: '{}' for app '{}'", domain, app.name);
            }

            // Add IP ranges if configured
            if let Some(ranges) = &app.ip_ranges {
                debug!("[SaaSDetector] App '{}' has {} IP ranges configured", app.name, ranges.len());
                for range_str in ranges {
                    match range_str.parse::<ipnetwork::Ipv4Network>() {
                        Ok(network) => {
                            ip_ranges.push((network, app.name.clone()));
                            debug!("[SaaSDetector] Added IP range: '{}' for app '{}'", range_str, app.name);
                        }
                        Err(e) => {
                            warn!("Failed to parse IP range '{}': {}", range_str, e);
                        }
                    }
                }
            } else {
                debug!("[SaaSDetector] App '{}' has NO ip_ranges field (None)", app.name);
            }
        }

        info!("[SaaSDetector] Loaded {} domain patterns and {} IP ranges", 
            domain_map.len(), ip_ranges.len());

        SaaSDetector {
            config,
            domain_map,
            ip_ranges,
        }
    }

    /// Detect SaaS traffic from a connection event with optional resolved domain
    pub fn detect(&self, event: &ConnectionEvent, resolved_domain: Option<&str>) -> Option<SaaSDetection> {
        // First, check if we have a resolved domain (from DNS or SNI)
        if let Some(domain) = resolved_domain {
            if let Some(detection) = self.detect_by_domain(domain, event) {
                return Some(detection);
            }
        }

        // Also check the domain_hint from the event (SNI or DNS)
        if let Some(domain) = &event.domain_hint {
            if let Some(detection) = self.detect_by_domain(domain, event) {
                return Some(detection);
            }
        }

        // Fall back to IP-based detection
        self.detect_by_ip(event.dest_ip, event)
    }

    /// Detect by domain name matching
    fn detect_by_domain(&self, domain: &str, event: &ConnectionEvent) -> Option<SaaSDetection> {
        let domain_lower = domain.to_lowercase();

        for (pattern, app_name) in &self.domain_map {
            let pattern_lower = pattern.to_lowercase();

            // Check multiple matching strategies
            if domain_lower == pattern_lower ||
               domain_lower.ends_with(&format!(".{}", pattern_lower)) ||
               domain_lower.contains(&format!(".{}", pattern_lower)) ||
               domain_lower.contains(&format!("{}", pattern_lower)) {

                info!("✓ DETECTED: {} ({}) matched pattern '{}'",
                    app_name, domain, pattern);

                return Some(SaaSDetection {
                    app_name: app_name.clone(),
                    confidence: DetectionConfidence::High,
                    source: DetectionSource::DomainName,
                    matched_pattern: pattern.clone(),
                    event: event.clone(),
                });
            }
        }

        debug!("No match for domain: '{}'", domain);
        None
    }

    /// Detect by IP address range matching
    fn detect_by_ip(&self, ip: IpAddr, event: &ConnectionEvent) -> Option<SaaSDetection> {
        if let IpAddr::V4(ipv4) = ip {
            for (network, app_name) in &self.ip_ranges {
                if network.contains(ipv4) {
                    info!("✓ IP DETECTED: {} (IP: {}) in range {} -> {}",
                        app_name, ip, network, app_name);

                    return Some(SaaSDetection {
                        app_name: app_name.clone(),
                        confidence: DetectionConfidence::Medium,
                        source: DetectionSource::IPAddress,
                        matched_pattern: network.to_string(),
                        event: event.clone(),
                    });
                }
            }
        }

        // Log unmatched IPs at debug level for troubleshooting
        debug!("No IP range match for: {} (dest: {}:{} -> {}:{})", 
            ip, event.source_ip, event.source_port, event.dest_ip, event.dest_port);
        None
    }

    /// Get all configured domain patterns (for debugging)
    pub fn get_domain_patterns(&self) -> Vec<&String> {
        self.domain_map.iter().map(|(d, _)| d).collect()
    }

    /// Get all configured IP ranges (for debugging)
    pub fn get_ip_ranges(&self) -> Vec<&ipnetwork::Ipv4Network> {
        self.ip_ranges.iter().map(|(r, _)| r).collect()
    }
}