use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::fs;
use std::path::Path;
use std::sync::Once;
use std::sync::Mutex;

static INIT: Once = Once::new();
static INIT_RESULT: Mutex<Option<Result<(), String>>> = Mutex::new(None);

pub fn setup_logging(_console_verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    INIT.call_once(|| {
        let result = (|| {
            // Create log directory if it doesn't exist
            let log_dir = Path::new("C:\\ProgramData\\SaaSMonitor\\logs");
            fs::create_dir_all(log_dir).map_err(|e| format!("Failed to create log directory: {}", e))?;

            // Configure file appender
            let logfile = FileAppender::builder()
                .encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S)} - {l} - {m}\n")))
                .append(true)
                .build("C:\\ProgramData\\SaaSMonitor\\logs\\saas-monitor.log")
                .map_err(|e| format!("Failed to create log file: {}", e))?;

            // Build configuration - Debug level for troubleshooting
            let config = Config::builder()
                .appender(Appender::builder().build("file", Box::new(logfile)))
                .build(Root::builder().appender("file").build(log::LevelFilter::Debug))
                .map_err(|e| format!("Failed to build log config: {}", e))?;

            // Initialize logging
            log4rs::init_config(config).map_err(|e| format!("Logging initialization failed: {}", e))?;

            Ok(())
        })();

        // Store the result
        *INIT_RESULT.lock().unwrap() = Some(result);
    });

    // Retrieve and return the result
    let guard = INIT_RESULT.lock().unwrap();
    match guard.as_ref() {
        Some(Ok(())) => Ok(()),
        Some(Err(msg)) => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, msg.clone()))),
        None => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Logging not initialized"))),
    }
}

// Helper macros for different log levels
#[macro_export]
macro_rules! log_connection {
    ($event:expr) => {
        log::info!("Connection: {}:{} -> {}:{}", 
            $event.source_ip, $event.source_port, $event.dest_ip, $event.dest_port);
    };
}

#[macro_export]
macro_rules! log_detection {
    ($app:expr, $domain:expr) => {
        log::info!("✅ DETECTED: {} ({})", $app, $domain);
        println!("\n⚠️  \x1b[91mDETECTED: {} ({})\x1b[0m", $app, $domain);
    };
}

#[macro_export]
macro_rules! log_domain_check {
    ($domain:expr) => {
        log::debug!("Checking domain: {}", $domain);
    };
}

#[macro_export]
macro_rules! log_match {
    ($domain:expr, $pattern:expr, $app:expr) => {
        log::info!("✓ Match: {} ~ {} -> {}", $domain, $pattern, $app);
    };
}

#[macro_export]
macro_rules! log_no_match {
    ($domain:expr) => {
        log::debug!("✗ No match for: {}", $domain);
    };
}