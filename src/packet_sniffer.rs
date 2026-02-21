//! Packet Sniffer Module - Deprecated
//! 
//! This module has been deprecated in favor of direct TCP table polling
//! via process_monitor.rs which uses GetExtendedTcpTable Windows API.
//! 
//! The TCP table approach:
//! - Works cross-session without admin privileges
//! - No packet capture driver dependencies
//! - More reliable on Windows
//! - Lower latency (no packet parsing overhead)
//!
//! ConnectionEvent is kept for compatibility with the detection pipeline.

use std::net::IpAddr;

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

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    TCP,
    UDP,
}
