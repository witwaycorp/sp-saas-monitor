use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LocalFree};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS
};
use windows::Win32::System::Memory::{LocalAlloc, LPTR};
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP_STATE, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_SYN_SENT,
    MIB_TCP_STATE_SYN_RCVD, TCP_TABLE_CLASS,
};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use log::debug;

// TCP table class constant
const TCP_TABLE_OWNER_PID_ALL: TCP_TABLE_CLASS = TCP_TABLE_CLASS(5);

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub command_line: Option<String>,
    pub start_time: chrono::DateTime<chrono::Local>,
    pub parent_pid: u32,
}

/// TCP connection with process info - works across ALL sessions
#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub local_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_addr: Ipv4Addr,
    pub remote_port: u16,
    pub state: MIB_TCP_STATE,
    pub pid: u32,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
}

// Ensure ProcessMonitor is Send and Sync
unsafe impl Send for ProcessMonitor {}
unsafe impl Sync for ProcessMonitor {}

pub struct ProcessMonitor {
    process_cache: Arc<RwLock<HashMap<u32, (ProcessInfo, Instant)>>>,
    cache_duration: Duration,
    tcp_table_cache: Arc<RwLock<HashMap<u16, u32>>>, // port -> pid mapping
    connection_sender: Option<mpsc::Sender<TcpConnection>>,
}

impl ProcessMonitor {
    pub fn new(cache_duration_seconds: u64) -> Self {
        ProcessMonitor {
            process_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_duration: Duration::from_secs(cache_duration_seconds),
            tcp_table_cache: Arc::new(RwLock::new(HashMap::new())),
            connection_sender: None,
        }
    }

    /// Create ProcessMonitor with connection event sender for real-time monitoring
    pub fn with_connection_sender(
        cache_duration_seconds: u64,
        sender: mpsc::Sender<TcpConnection>,
    ) -> Self {
        ProcessMonitor {
            process_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_duration: Duration::from_secs(cache_duration_seconds),
            tcp_table_cache: Arc::new(RwLock::new(HashMap::new())),
            connection_sender: Some(sender),
        }
    }

    /// Poll TCP table and return all connections with process info
    /// This works across ALL sessions - key for detecting MCP agent traffic
    pub async fn poll_tcp_connections(&self) -> Vec<TcpConnection> {
        let tcp_table_cache = self.tcp_table_cache.clone();
        let _process_cache = self.process_cache.clone();
        let _cache_duration = self.cache_duration;
        let sender = self.connection_sender.clone();
        
        tokio::task::spawn_blocking(move || {
            unsafe {
                let mut size: u32 = 0;

                // First call to get required size
                let result = GetExtendedTcpTable(
                    None,
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );

                if result != 0 && result != 122 { // 122 = ERROR_INSUFFICIENT_BUFFER
                    return Vec::new();
                }

                // Allocate buffer
                let hmem = match LocalAlloc(LPTR, size as usize) {
                    Ok(h) => h,
                    Err(_) => return Vec::new(),
                };

                let tcp_table_ptr = hmem.0 as *mut std::ffi::c_void;

                // Get actual table
                let result = GetExtendedTcpTable(
                    Some(tcp_table_ptr),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );

                if result != 0 {
                    let _ = LocalFree(hmem);
                    return Vec::new();
                }

                let mut connections = Vec::new();
                let mut port_map = HashMap::new();

                // Parse the table
                let table = tcp_table_ptr as *const MIB_TCPTABLE_OWNER_PID;
                if !table.is_null() {
                    let num_entries = (*table).dwNumEntries as usize;

                    for i in 0..num_entries {
                        let entry = (*table).table.as_ptr().add(i);
                        if !entry.is_null() {
                            let local_addr = Ipv4Addr::from(u32::from_be((*entry).dwLocalAddr));
                            // Port is in lower 16 bits, in network byte order - use ntohs equivalent
                            let local_port = u16::from_be((*entry).dwLocalPort as u16);
                            let remote_addr = Ipv4Addr::from(u32::from_be((*entry).dwRemoteAddr));
                            let remote_port = u16::from_be((*entry).dwRemotePort as u16);
                            let state = MIB_TCP_STATE((*entry).dwState as i32);
                            let pid = (*entry).dwOwningPid;

                            // Get process info for established or connecting connections
                            let (process_name, process_path) = if 
                                state == MIB_TCP_STATE_ESTAB ||
                                state == MIB_TCP_STATE_SYN_SENT ||
                                state == MIB_TCP_STATE_SYN_RCVD 
                            {
                                match Self::query_process_info_blocking_sync(pid) {
                                    Some(proc) => (Some(proc.name.clone()), Some(proc.path.clone())),
                                    None => (None, None),
                                }
                            } else {
                                (None, None)
                            };

                            let conn = TcpConnection {
                                local_addr,
                                local_port,
                                remote_addr,
                                remote_port,
                                state,
                                pid,
                                process_name: process_name.clone(),
                                process_path,
                            };

                            // Store in port map for quick lookup
                            if local_port > 0 && local_port < 50000 {
                                port_map.insert(local_port, pid);
                            }

                            connections.push(conn);
                        }
                    }
                }

                // Update TCP cache
                {
                    let rt = tokio::runtime::Handle::current();
                    let _ = rt.block_on(async {
                        let mut cache = tcp_table_cache.write().await;
                        *cache = port_map;
                    });
                }

                // Send connections to event channel if configured
                if let Some(tx) = sender {
                    for conn in &connections {
                        let _ = tx.try_send(conn.clone());
                    }
                }

                // Free the memory
                let _ = LocalFree(hmem);

                connections
            }
        }).await.unwrap_or_default()
    }

    pub async fn get_process_for_port(&self, local_port: u16) -> Option<ProcessInfo> {
        // Skip obviously fake/mock ports (50000+ are our mock ports)
        if local_port >= 50000 {
            println!("   [Mock Mode] Skipping process lookup for mock port {}", local_port);
            return None;
        }
        
        // First, refresh TCP table to get latest mappings
        self.refresh_tcp_table().await;
        
        // Check cache for port->pid mapping
        let tcp_cache = self.tcp_table_cache.read().await;
        if let Some(&pid) = tcp_cache.get(&local_port) {
            drop(tcp_cache);
            return self.get_process_by_pid(pid).await;
        }
        
        None
    }

    async fn refresh_tcp_table(&self) {
        let tcp_cache = self.tcp_table_cache.clone();
        
        // Use spawn_blocking for blocking Windows API calls
        let _ = tokio::task::spawn_blocking(move || {
            unsafe {
                let mut size: u32 = 0;
                
                // First call to get required size
                let result = GetExtendedTcpTable(
                    None,
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );

                if result != 0 && result != 122 { // 122 = ERROR_INSUFFICIENT_BUFFER
                    return;
                }

                // Allocate buffer
                let hmem = match LocalAlloc(LPTR, size as usize) {
                    Ok(h) => h,
                    Err(_) => return,
                };
                
                let tcp_table_ptr = hmem.0 as *mut std::ffi::c_void;

                // Get actual table
                let result = GetExtendedTcpTable(
                    Some(tcp_table_ptr),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );

                if result == 0 {
                    let mut port_map = HashMap::new();
                    
                    // Parse the table
                    let table = tcp_table_ptr as *const MIB_TCPTABLE_OWNER_PID;
                    if !table.is_null() {
                        let num_entries = (*table).dwNumEntries as usize;
                        
                        for i in 0..num_entries {
                            let entry = (*table).table.as_ptr().add(i);
                            if !entry.is_null() {
                                // Port is in lower 16 bits, in network byte order
                                let local_port = u16::from_be((*entry).dwLocalPort as u16);
                                let pid = (*entry).dwOwningPid;

                                // Only store established connections (state 5 = MIB_TCP_STATE_ESTAB)
                                if (*entry).dwState == 5 && local_port > 0 && local_port < 50000 {
                                    port_map.insert(local_port, pid);
                                }
                            }
                        }
                    }
                    
                    // Update cache
                    let rt = tokio::runtime::Handle::current();
                    let _ = rt.block_on(async {
                        let mut cache = tcp_cache.write().await;
                        *cache = port_map;
                    });
                }

                // Free the memory
                let _ = LocalFree(hmem);
            }
        }).await;
    }

    async fn get_process_by_pid(&self, pid: u32) -> Option<ProcessInfo> {
        // Skip invalid PIDs (0-4 are system processes, > 100000 are usually fake)
        if pid == 0 || pid == 4 || pid > 100000 {
            return None;
        }

        // Check cache first
        {
            let cache = self.process_cache.read().await;
            if let Some((info, timestamp)) = cache.get(&pid) {
                if timestamp.elapsed() < self.cache_duration {
                    return Some(info.clone());
                }
            }
        }

        // Get from system in a blocking thread
        let pid_clone = pid;

        let result = tokio::task::spawn_blocking(move || {
            Self::query_process_info_blocking_sync(pid_clone)
        }).await;

        match result {
            Ok(Some(info)) => {
                let mut cache = self.process_cache.write().await;
                cache.insert(pid, (info.clone(), Instant::now()));
                Some(info)
            }
            Ok(None) => None,
            Err(e) => {
                debug!("Error in spawn_blocking: {}", e);
                None
            }
        }
    }

    // Synchronous version for use in spawn_blocking
    fn query_process_info_blocking_sync(pid: u32) -> Option<ProcessInfo> {
        // Don't try to query system process (PID 0) or idle process (PID 4 on some systems)
        if pid == 0 || pid == 4 {
            return None;
        }

        unsafe {
            // Open process with required permissions
            let handle = match OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid
            ) {
                Ok(h) => h,
                Err(_) => return None,
            };

            if handle == INVALID_HANDLE_VALUE || handle.0 == 0 {
                return None;
            }

            let mut info = None;

            // Get process image name (full path)
            let mut exe_path_buf = [0u16; 260];
            let path_size = GetModuleFileNameExW(
                handle,
                None,
                &mut exe_path_buf
            );

            if path_size > 0 {
                let path = String::from_utf16_lossy(&exe_path_buf[..path_size as usize]);

                // Extract filename from path
                let name = std::path::Path::new(&path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                // Get parent process ID using toolhelp snapshot
                let parent_pid = Self::get_parent_pid_blocking(pid).unwrap_or(0);

                info = Some(ProcessInfo {
                    pid,
                    name,
                    path,
                    command_line: None,
                    start_time: chrono::Local::now(),
                    parent_pid,
                });
            }

            let _ = CloseHandle(handle);
            info
        }
    }

    async fn query_process_info_blocking(
        pid: u32,
        process_cache: &Arc<RwLock<HashMap<u32, (ProcessInfo, Instant)>>>,
        cache_duration: Duration,
    ) -> Option<ProcessInfo> {
        // Check cache first
        {
            let cache = process_cache.read().await;
            if let Some((info, timestamp)) = cache.get(&pid) {
                if timestamp.elapsed() < cache_duration {
                    return Some(info.clone());
                }
            }
        }

        // Don't try to query system process (PID 0) or idle process (PID 4 on some systems)
        if pid == 0 || pid == 4 {
            return None;
        }

        unsafe {
            // Open process with required permissions
            let handle = match OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                pid
            ) {
                Ok(h) => h,
                Err(_) => return None,
            };

            if handle == INVALID_HANDLE_VALUE || handle.0 == 0 {
                return None;
            }

            let mut info = None;

            // Get process image name (full path)
            let mut exe_path_buf = [0u16; 260];
            let path_size = GetModuleFileNameExW(
                handle,
                None,
                &mut exe_path_buf
            );

            if path_size > 0 {
                let path = String::from_utf16_lossy(&exe_path_buf[..path_size as usize]);

                // Extract filename from path
                let name = std::path::Path::new(&path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                // Get parent process ID using toolhelp snapshot
                let parent_pid = Self::get_parent_pid_blocking(pid).unwrap_or(0);

                info = Some(ProcessInfo {
                    pid,
                    name,
                    path,
                    command_line: None,
                    start_time: chrono::Local::now(),
                    parent_pid,
                });
            }

            let _ = CloseHandle(handle);
            info
        }
    }

    fn get_parent_pid_blocking(pid: u32) -> Option<u32> {
        unsafe {
            let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(s) => s,
                Err(_) => return None,
            };

            if snapshot == INVALID_HANDLE_VALUE || snapshot.0 == 0 {
                return None;
            }

            let mut process_entry: PROCESSENTRY32W = std::mem::zeroed();
            process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            let mut parent_pid = None;
            
            if Process32FirstW(snapshot, &mut process_entry).is_ok() {
                loop {
                    if process_entry.th32ProcessID == pid {
                        parent_pid = Some(process_entry.th32ParentProcessID);
                        break;
                    }

                    if Process32NextW(snapshot, &mut process_entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
            parent_pid
        }
    }

    // Get all processes for debugging/monitoring
    pub async fn get_all_processes(&self) -> Vec<ProcessInfo> {
        tokio::task::spawn_blocking(move || {
            let mut processes = Vec::new();
            
            unsafe {
                let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                    Ok(s) => s,
                    Err(_) => return processes,
                };

                if snapshot == INVALID_HANDLE_VALUE || snapshot.0 == 0 {
                    return processes;
                }

                let mut process_entry: PROCESSENTRY32W = std::mem::zeroed();
                process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

                if Process32FirstW(snapshot, &mut process_entry).is_ok() {
                    loop {
                        let pid = process_entry.th32ProcessID;
                        
                        // Get process name
                        let name = String::from_utf16_lossy(&process_entry.szExeFile)
                            .trim_end_matches('\0')
                            .to_string();

                        // Get full path
                        let path = Self::get_process_path_blocking(pid).unwrap_or_else(|| name.clone());

                        processes.push(ProcessInfo {
                            pid,
                            name: name.clone(),
                            path,
                            command_line: None,
                            start_time: chrono::Local::now(),
                            parent_pid: process_entry.th32ParentProcessID,
                        });

                        if Process32NextW(snapshot, &mut process_entry).is_err() {
                            break;
                        }
                    }
                }

                let _ = CloseHandle(snapshot);
            }

            processes
        }).await.unwrap_or_default()
    }

    fn get_process_path_blocking(pid: u32) -> Option<String> {
        // Don't try to query system process
        if pid == 0 || pid == 4 {
            return None;
        }

        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                Ok(h) => h,
                Err(_) => return None,
            };

            if handle == INVALID_HANDLE_VALUE || handle.0 == 0 {
                return None;
            }
            
            let mut path_buf = [0u16; 260];
            let result = GetModuleFileNameExW(
                handle,
                None,
                &mut path_buf
            );

            let _ = CloseHandle(handle);

            if result > 0 {
                Some(String::from_utf16_lossy(&path_buf[..result as usize]))
            } else {
                None
            }
        }
    }
}

#[repr(C)]
struct MIB_TCPROW_OWNER_PID {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
}

#[repr(C)]
struct MIB_TCPTABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_TCPROW_OWNER_PID; 1],
}