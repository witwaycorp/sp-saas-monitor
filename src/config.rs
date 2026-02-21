use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub saas_apps: Vec<SaaSApp>,
    pub monitoring: MonitoringConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SaaSApp {
    pub name: String,
    pub domains: Vec<String>,
    pub ip_ranges: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MonitoringConfig {
    pub interface: Option<String>,
    pub capture_dns: bool,
    pub capture_tls_sni: bool,
    pub process_cache_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoggingConfig {
    pub log_file: Option<String>,
    pub log_level: String,
    pub alert_on_detection: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&contents)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Config {
            saas_apps: vec![
                SaaSApp {
                    name: "Salesforce".to_string(),
                    domains: vec![
                        "salesforce.com".to_string(),
                        "login.salesforce.com".to_string(),
                        "force.com".to_string(),
                    ],
                    ip_ranges: None,
                },
                SaaSApp {
                    name: "Microsoft 365".to_string(),
                    domains: vec![
                        "microsoftonline.com".to_string(),
                        "office.com".to_string(),
                        "sharepoint.com".to_string(),
                        "teams.microsoft.com".to_string(),
                    ],
                    ip_ranges: None,
                },
            ],
            monitoring: MonitoringConfig {
                interface: None,
                capture_dns: true,
                capture_tls_sni: true,
                process_cache_seconds: 60,
            },
            logging: LoggingConfig {
                log_file: Some("C:\\ProgramData\\SaaSMonitor\\logs\\monitor.log".to_string()),
                log_level: "info".to_string(),
                alert_on_detection: true,
            },
        }
    }
}