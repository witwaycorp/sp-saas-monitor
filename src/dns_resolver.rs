//! DNS Resolver for IP-to-Domain resolution
//! 
//! This module provides reverse DNS lookup and caching for resolving
//! remote IP addresses to domain names, which can then be matched
//! against SaaS domain patterns.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use log::debug;
use trust_dns_resolver::TokioAsyncResolver;

/// Cached DNS result
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub domain: Option<String>, // None = lookup failed or timed out
    pub timestamp: Instant,
    pub ttl_seconds: u64,
}

/// DNS Resolver with caching
pub struct DnsResolver {
    cache: Arc<RwLock<HashMap<IpAddr, DnsCacheEntry>>>,
    cache_ttl: Duration,
    resolver: TokioAsyncResolver,
}

unsafe impl Send for DnsResolver {}
unsafe impl Sync for DnsResolver {}

impl DnsResolver {
    pub fn new(cache_ttl_seconds: u64) -> Self {
        // Create a DNS resolver with system config
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
            // Fallback to Google DNS if system config fails
            use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
            TokioAsyncResolver::tokio(
                ResolverConfig::google(),
                ResolverOpts::default(),
            )
        });

        DnsResolver {
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(cache_ttl_seconds),
            resolver,
        }
    }

    /// Resolve IP to domain name with caching using reverse DNS (PTR)
    /// Uses aggressive timeouts: 500ms for uncached, immediate return for cached failures
    pub async fn resolve(&self, ip: IpAddr) -> Option<String> {
        // Check cache first (including failed lookups)
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&ip) {
                if entry.timestamp.elapsed() < Duration::from_secs(entry.ttl_seconds) {
                    if let Some(ref domain) = entry.domain {
                        debug!("DNS cache hit for {}: {}", ip, domain);
                    }
                    return entry.domain.clone();
                }
            }
        }

        // Perform reverse DNS lookup with aggressive 500ms timeout for faster detection
        let resolve_future = self.resolver.reverse_lookup(ip);
        let result = match tokio::time::timeout(Duration::from_millis(500), resolve_future).await {
            Ok(result) => result,
            Err(_) => {
                debug!("DNS lookup timeout (500ms) for {}", ip);
                // Cache the timeout to avoid repeated attempts (shorter cache for timeout)
                let mut cache = self.cache.write().await;
                cache.insert(
                    ip,
                    DnsCacheEntry {
                        domain: None,
                        timestamp: Instant::now(),
                        ttl_seconds: 60, // Cache timeout for 1 minute
                    },
                );
                return None;
            }
        };

        match result {
            Ok(lookup) => {
                // Collect into Vec and get first result
                let names: Vec<_> = lookup.into_iter().collect();
                if let Some(name) = names.first() {
                    let domain: String = name.to_string().trim_end_matches('.').to_string();
                    debug!("DNS resolved {} -> {}", ip, domain);

                    // Cache the result (10 minutes for success)
                    let mut cache = self.cache.write().await;
                    cache.insert(
                        ip,
                        DnsCacheEntry {
                            domain: Some(domain.clone()),
                            timestamp: Instant::now(),
                            ttl_seconds: 600,
                        },
                    );

                    return Some(domain);
                }
            }
            Err(e) => {
                debug!("DNS reverse lookup failed for {}: {}", ip, e);
            }
        }

        // Cache the failure (1 minute for failed lookups to avoid repeated attempts)
        let mut cache = self.cache.write().await;
        cache.insert(
            ip,
            DnsCacheEntry {
                domain: None,
                timestamp: Instant::now(),
                ttl_seconds: 60,
            },
        );

        None
    }

    /// Resolve IP to domain in background (fire-and-forget for caching)
    /// Returns immediately with cached value (if any), updates cache asynchronously
    pub async fn resolve_background(&self, ip: IpAddr) -> Option<String> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&ip) {
                if entry.timestamp.elapsed() < Duration::from_secs(entry.ttl_seconds) {
                    return entry.domain.clone();
                }
            }
        }

        // Spawn background task to update cache
        let resolver = self.resolver.clone();
        let cache = self.cache.clone();

        tokio::spawn(async move {
            let resolve_future = resolver.reverse_lookup(ip);
            let result = match tokio::time::timeout(Duration::from_millis(500), resolve_future).await {
                Ok(result) => result,
                Err(_) => {
                    debug!("Background DNS lookup timeout for {}", ip);
                    let mut c = cache.write().await;
                    c.insert(
                        ip,
                        DnsCacheEntry {
                            domain: None,
                            timestamp: Instant::now(),
                            ttl_seconds: 60,
                        },
                    );
                    return;
                }
            };

            match result {
                Ok(lookup) => {
                    let names: Vec<_> = lookup.into_iter().collect();
                    if let Some(name) = names.first() {
                        let domain: String = name.to_string().trim_end_matches('.').to_string();
                        let mut c = cache.write().await;
                        c.insert(
                            ip,
                            DnsCacheEntry {
                                domain: Some(domain.clone()),
                                timestamp: Instant::now(),
                                ttl_seconds: 600,
                            },
                        );
                    }
                }
                Err(e) => {
                    debug!("Background DNS lookup failed for {}: {}", ip, e);
                    let mut c = cache.write().await;
                    c.insert(
                        ip,
                        DnsCacheEntry {
                            domain: None,
                            timestamp: Instant::now(),
                            ttl_seconds: 60,
                        },
                    );
                }
            }
        });

        // Return cached value immediately (may be None if not cached yet)
        let cache = self.cache.read().await;
        cache.get(&ip).and_then(|e| {
            if e.timestamp.elapsed() < Duration::from_secs(e.ttl_seconds) {
                e.domain.clone()
            } else {
                None
            }
        })
    }

    /// Clear the DNS cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        debug!("DNS cache cleared");
    }

    /// Get cache statistics
    pub async fn cache_size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_resolver() {
        let resolver = DnsResolver::new(300);
        
        // Test with a known IP (Google DNS)
        let google_dns = "8.8.8.8".parse().unwrap();
        let result = resolver.resolve(google_dns).await;
        
        // Should resolve to dns.google or similar
        assert!(result.is_some());
        println!("Resolved 8.8.8.8 to: {:?}", result);
    }
}
