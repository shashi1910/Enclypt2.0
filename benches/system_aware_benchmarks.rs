use criterion::{black_box, criterion_group, criterion_main, Criterion};
use enclypt2::{
    crypto::{
        generate_crypto_identity, get_algorithm_info,
        encapsulate, decapsulate, sign, verify,
        encrypt_data, decrypt_data, derive_aes_key,
        generate_aes_key,
    },
    file_processor::FileProcessor,
};
use tempfile::tempdir;
use std::fs;
use std::time::Instant;
use std::process::Command;
use std::path::Path;
use serde::{Serialize, Deserialize};
use chrono::Utc;

// Test data sizes for comprehensive benchmarking
const TEST_SIZES: [usize; 8] = [64, 256, 1024, 4096, 16384, 65536, 262144, 1048576]; // 64B to 1MB

#[derive(Serialize, Deserialize, Clone)]
struct SystemInfo {
    timestamp: String,
    os_name: String,
    os_version: String,
    architecture: String,
    cpu_model: String,
    cpu_cores: usize,
    total_memory_gb: f64,
    rust_version: String,
    enclypt2_version: String,
    hostname: String,
    username: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct BenchmarkResult {
    test_name: String,
    operation: String,
    data_size_bytes: usize,
    mean_time_microseconds: f64,
    median_time_microseconds: f64,
    p95_time_microseconds: f64,
    p99_time_microseconds: f64,
    min_time_microseconds: f64,
    max_time_microseconds: f64,
    throughput_ops_per_sec: f64,
    throughput_mbps: Option<f64>,
    memory_usage_bytes: Option<usize>,
    iterations: usize,
    warmup_time_seconds: u64,
    measurement_time_seconds: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct ComprehensiveReport {
    system_info: SystemInfo,
    benchmark_results: Vec<BenchmarkResult>,
    summary: ReportSummary,
}

#[derive(Serialize, Deserialize, Clone)]
struct ReportSummary {
    total_tests: usize,
    total_operations: usize,
    average_throughput_ops_per_sec: f64,
    fastest_operation: String,
    slowest_operation: String,
    total_duration_seconds: f64,
    algorithm_info: String,
}

fn collect_system_info() -> SystemInfo {
    let timestamp = Utc::now().to_rfc3339();
    
    // Get OS information
    let os_name = std::env::consts::OS.to_string();
    let os_version = get_os_version();
    let architecture = std::env::consts::ARCH.to_string();
    
    // Get CPU information
    let cpu_info = get_cpu_info();
    let cpu_cores = num_cpus::get();
    
    // Get memory information
    let total_memory_gb = get_total_memory_gb();
    
    // Get Rust version
    let rust_version = get_rust_version();
    
    // Get Enclypt2 version from Cargo.toml
    let enclypt2_version = get_enclypt2_version();
    
    // Get hostname and username
    let hostname = get_hostname();
    let username = get_username();
    
    SystemInfo {
        timestamp,
        os_name,
        os_version,
        architecture,
        cpu_model: cpu_info,
        cpu_cores,
        total_memory_gb,
        rust_version,
        enclypt2_version,
        hostname,
        username,
    }
}

fn get_os_version() -> String {
    match std::env::consts::OS {
        "linux" => {
            if let Ok(output) = Command::new("cat").arg("/etc/os-release").output() {
                if let Ok(content) = String::from_utf8(output.stdout) {
                    for line in content.lines() {
                        if line.starts_with("PRETTY_NAME=") {
                            return line.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string();
                        }
                    }
                }
            }
            "Linux (Unknown Distribution)".to_string()
        },
        "macos" => {
            if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    return format!("macOS {}", version.trim());
                }
            }
            "macOS (Unknown Version)".to_string()
        },
        "windows" => {
            if let Ok(output) = Command::new("ver").output() {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    return version.trim().to_string();
                }
            }
            "Windows (Unknown Version)".to_string()
        },
        _ => "Unknown OS".to_string(),
    }
}

fn get_cpu_info() -> String {
    match std::env::consts::OS {
        "linux" => {
            if let Ok(output) = Command::new("cat").arg("/proc/cpuinfo").output() {
                if let Ok(content) = String::from_utf8(output.stdout) {
                    for line in content.lines() {
                        if line.starts_with("model name") {
                            return line.split(':').nth(1).unwrap_or("Unknown CPU").trim().to_string();
                        }
                    }
                }
            }
        },
        "macos" => {
            if let Ok(output) = Command::new("sysctl").arg("-n").arg("machdep.cpu.brand_string").output() {
                if let Ok(cpu) = String::from_utf8(output.stdout) {
                    return cpu.trim().to_string();
                }
            }
        },
        "windows" => {
            if let Ok(output) = Command::new("wmic").args(&["cpu", "get", "name", "/format:list"]).output() {
                if let Ok(content) = String::from_utf8(output.stdout) {
                    for line in content.lines() {
                        if line.starts_with("Name=") {
                            return line.trim_start_matches("Name=").trim().to_string();
                        }
                    }
                }
            }
        },
        _ => {},
    }
    "Unknown CPU".to_string()
}

fn get_total_memory_gb() -> f64 {
    match std::env::consts::OS {
        "linux" => {
            if let Ok(output) = Command::new("cat").arg("/proc/meminfo").output() {
                if let Ok(content) = String::from_utf8(output.stdout) {
                    for line in content.lines() {
                        if line.starts_with("MemTotal:") {
                            if let Some(kb_str) = line.split_whitespace().nth(1) {
                                if let Ok(kb) = kb_str.parse::<f64>() {
                                    return kb / (1024.0 * 1024.0); // Convert KB to GB
                                }
                            }
                        }
                    }
                }
            }
        },
        "macos" => {
            if let Ok(output) = Command::new("sysctl").arg("-n").arg("hw.memsize").output() {
                if let Ok(bytes_str) = String::from_utf8(output.stdout) {
                    if let Ok(bytes) = bytes_str.trim().parse::<f64>() {
                        return bytes / (1024.0 * 1024.0 * 1024.0); // Convert bytes to GB
                    }
                }
            }
        },
        "windows" => {
            if let Ok(output) = Command::new("wmic").args(&["computersystem", "get", "TotalPhysicalMemory", "/format:list"]).output() {
                if let Ok(content) = String::from_utf8(output.stdout) {
                    for line in content.lines() {
                        if line.starts_with("TotalPhysicalMemory=") {
                            if let Some(bytes_str) = line.split('=').nth(1) {
                                if let Ok(bytes) = bytes_str.trim().parse::<f64>() {
                                    return bytes / (1024.0 * 1024.0 * 1024.0); // Convert bytes to GB
                                }
                            }
                        }
                    }
                }
            }
        },
        _ => {},
    }
    0.0
}

fn get_rust_version() -> String {
    if let Ok(output) = Command::new("rustc").arg("--version").output() {
        if let Ok(version) = String::from_utf8(output.stdout) {
            return version.trim().to_string();
        }
    }
    "Unknown Rust Version".to_string()
}

fn get_enclypt2_version() -> String {
    // Try to read version from Cargo.toml
    if let Ok(content) = fs::read_to_string("Cargo.toml") {
        for line in content.lines() {
            if line.trim().starts_with("version = ") {
                if let Some(version) = line.split('=').nth(1) {
                    return version.trim().trim_matches('"').to_string();
                }
            }
        }
    }
    "Unknown Version".to_string()
}

fn get_hostname() -> String {
    if let Ok(output) = Command::new("hostname").output() {
        if let Ok(hostname) = String::from_utf8(output.stdout) {
            return hostname.trim().to_string();
        }
    }
    "Unknown Hostname".to_string()
}

fn get_username() -> String {
    if let Ok(username) = std::env::var("USER") {
        return username;
    }
    if let Ok(username) = std::env::var("USERNAME") {
        return username;
    }
    "Unknown User".to_string()
}

fn create_comprehensive_report(system_info: SystemInfo, benchmark_results: Vec<BenchmarkResult>) -> ComprehensiveReport {
    let total_tests = benchmark_results.len();
    let total_operations = benchmark_results.iter().map(|r| r.iterations).sum();
    let average_throughput = benchmark_results.iter().map(|r| r.throughput_ops_per_sec).sum::<f64>() / total_tests as f64;
    
    let fastest_operation = benchmark_results.iter()
        .min_by(|a, b| a.mean_time_microseconds.partial_cmp(&b.mean_time_microseconds).unwrap())
        .map(|r| format!("{} - {}", r.test_name, r.operation))
        .unwrap_or_else(|| "N/A".to_string());
    
    let slowest_operation = benchmark_results.iter()
        .max_by(|a, b| a.mean_time_microseconds.partial_cmp(&b.mean_time_microseconds).unwrap())
        .map(|r| format!("{} - {}", r.test_name, r.operation))
        .unwrap_or_else(|| "N/A".to_string());
    
    let total_duration = benchmark_results.iter().map(|r| r.measurement_time_seconds as f64).sum();
    
    let summary = ReportSummary {
        total_tests,
        total_operations,
        average_throughput_ops_per_sec: average_throughput,
        fastest_operation,
        slowest_operation,
        total_duration_seconds: total_duration,
        algorithm_info: get_algorithm_info().to_string(),
    };
    
    ComprehensiveReport {
        system_info,
        benchmark_results,
        summary,
    }
}

fn save_comprehensive_report(report: &ComprehensiveReport) {
    // Create tests directory if it doesn't exist
    let tests_dir = Path::new("tests");
    if !tests_dir.exists() {
        fs::create_dir_all(tests_dir).expect("Failed to create tests directory");
    }
    
    // Generate timestamp for filename
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let report_filename = format!("enclypt2_benchmark_report_{}.txt", timestamp);
    let report_path = tests_dir.join(report_filename);
    
    // Generate the comprehensive text report
    let report_content = generate_comprehensive_text_report(report);
    
    // Save the report
    fs::write(&report_path, report_content).expect("Failed to write comprehensive report");
    
    println!("📊 Comprehensive benchmark report saved to: {}", report_path.display());
}

fn generate_comprehensive_text_report(report: &ComprehensiveReport) -> String {
    let mut content = String::new();
    
    // Header
    content.push_str("🔐 Enclypt 2.0 Comprehensive Benchmark Report\n");
    content.push_str("==============================================\n\n");
    
    // System Information
    content.push_str("SYSTEM INFORMATION\n");
    content.push_str("==================\n");
    content.push_str(&format!("Timestamp: {}\n", report.system_info.timestamp));
    content.push_str(&format!("Hostname: {}\n", report.system_info.hostname));
    content.push_str(&format!("Username: {}\n", report.system_info.username));
    content.push_str(&format!("OS: {} {}\n", report.system_info.os_name, report.system_info.os_version));
    content.push_str(&format!("Architecture: {}\n", report.system_info.architecture));
    content.push_str(&format!("CPU: {} ({} cores)\n", report.system_info.cpu_model, report.system_info.cpu_cores));
    content.push_str(&format!("Memory: {:.1} GB\n", report.system_info.total_memory_gb));
    content.push_str(&format!("Rust Version: {}\n", report.system_info.rust_version));
    content.push_str(&format!("Enclypt2 Version: {}\n", report.system_info.enclypt2_version));
    content.push_str("\n");
    
    // Test Summary
    content.push_str("TEST SUMMARY\n");
    content.push_str("============\n");
    content.push_str(&format!("Total Tests: {}\n", report.summary.total_tests));
    content.push_str(&format!("Total Operations: {}\n", report.summary.total_operations));
    content.push_str(&format!("Average Throughput: {:.0} ops/sec\n", report.summary.average_throughput_ops_per_sec));
    content.push_str(&format!("Fastest Operation: {}\n", report.summary.fastest_operation));
    content.push_str(&format!("Slowest Operation: {}\n", report.summary.slowest_operation));
    content.push_str(&format!("Total Duration: {:.2} seconds\n", report.summary.total_duration_seconds));
    content.push_str("\n");
    
    // Algorithm Information
    content.push_str("ALGORITHM INFORMATION\n");
    content.push_str("=====================\n");
    content.push_str(&report.summary.algorithm_info);
    content.push_str("\n\n");
    
    // Performance Results by Category
    content.push_str("PERFORMANCE RESULTS\n");
    content.push_str("==================\n\n");
    
    // Group results by test name
    let mut test_groups: std::collections::HashMap<String, Vec<&BenchmarkResult>> = std::collections::HashMap::new();
    for result in &report.benchmark_results {
        test_groups.entry(result.test_name.clone()).or_insert_with(Vec::new).push(result);
    }
    
    for (test_name, results) in test_groups {
        content.push_str(&format!("{} Tests\n", test_name));
        content.push_str(&format!("{}\n", "=".repeat(test_name.len() + 7)));
        
        for result in results {
            content.push_str(&format!("Operation: {}\n", result.operation));
            content.push_str(&format!("Data Size: {} bytes\n", result.data_size_bytes));
            content.push_str(&format!("Mean Time: {:.2} μs\n", result.mean_time_microseconds));
            content.push_str(&format!("Median Time: {:.2} μs\n", result.median_time_microseconds));
            content.push_str(&format!("95th Percentile: {:.2} μs\n", result.p95_time_microseconds));
            content.push_str(&format!("99th Percentile: {:.2} μs\n", result.p99_time_microseconds));
            content.push_str(&format!("Min Time: {:.2} μs\n", result.min_time_microseconds));
            content.push_str(&format!("Max Time: {:.2} μs\n", result.max_time_microseconds));
            content.push_str(&format!("Throughput: {:.0} ops/sec\n", result.throughput_ops_per_sec));
            
            if let Some(throughput_mbps) = result.throughput_mbps {
                content.push_str(&format!("Data Throughput: {:.2} MB/s\n", throughput_mbps));
            }
            
            if let Some(memory_usage) = result.memory_usage_bytes {
                content.push_str(&format!("Memory Usage: {} bytes\n", memory_usage));
            }
            
            content.push_str(&format!("Iterations: {}\n", result.iterations));
            content.push_str(&format!("Warmup Time: {} seconds\n", result.warmup_time_seconds));
            content.push_str(&format!("Measurement Time: {} seconds\n", result.measurement_time_seconds));
            content.push_str("\n");
        }
    }
    
    // Performance Summary Table
    content.push_str("PERFORMANCE SUMMARY TABLE\n");
    content.push_str("=========================\n");
    content.push_str("Test | Operation | Data Size | Mean (μs) | Throughput (ops/sec) | Throughput (MB/s)\n");
    content.push_str("-----|-----------|-----------|-----------|---------------------|------------------\n");
    
    for result in &report.benchmark_results {
        let data_size_str = if result.data_size_bytes == 0 {
            "N/A".to_string()
        } else if result.data_size_bytes < 1024 {
            format!("{}B", result.data_size_bytes)
        } else if result.data_size_bytes < 1024 * 1024 {
            format!("{}KB", result.data_size_bytes / 1024)
        } else {
            format!("{}MB", result.data_size_bytes / (1024 * 1024))
        };
        
        let throughput_mbps_str = result.throughput_mbps
            .map(|t| format!("{:.2}", t))
            .unwrap_or_else(|| "N/A".to_string());
        
        content.push_str(&format!("{} | {} | {} | {:.2} | {:.0} | {}\n",
            result.test_name,
            result.operation,
            data_size_str,
            result.mean_time_microseconds,
            result.throughput_ops_per_sec,
            throughput_mbps_str
        ));
    }
    
    content.push_str("\n");
    
    // Recommendations
    content.push_str("RECOMMENDATIONS\n");
    content.push_str("===============\n");
    content.push_str("1. Performance Analysis: Review the detailed results above for performance insights\n");
    content.push_str("2. Bottleneck Identification: Focus on operations with highest latency\n");
    content.push_str("3. Optimization Opportunities: Target the slowest operations for improvement\n");
    content.push_str("4. Memory Usage: Monitor memory consumption for large file operations\n");
    content.push_str("5. Cross-Platform Testing: Compare results across different systems\n");
    content.push_str("6. Security Validation: Ensure all cryptographic operations meet security requirements\n\n");
    
    // Footer
    content.push_str("Report generated by Enclypt 2.0 System-Aware Benchmarking System\n");
    content.push_str(&format!("Generated on: {}\n", report.system_info.timestamp));
    
    content
}

fn run_benchmark_with_reporting<F>(
    test_name: &str,
    operation: &str,
    data_size: usize,
    iterations: usize,
    warmup_time: u64,
    measurement_time: u64,
    mut benchmark_fn: F,
) -> BenchmarkResult 
where
    F: FnMut() -> (std::time::Duration, Option<usize>),
{
    let mut times = Vec::new();
    let mut memory_usage = None;
    
    // Warmup
    for _ in 0..(warmup_time * 1000) { // Convert to iterations
        benchmark_fn();
    }
    
    // Actual measurements
    for _ in 0..iterations {
        let (duration, memory) = benchmark_fn();
        times.push(duration);
        if memory.is_some() {
            memory_usage = memory;
        }
    }
    
    times.sort();
    
    let mean_time = times.iter().sum::<std::time::Duration>() / iterations as u32;
    let median_time = times[iterations / 2];
    let p95_time = times[(iterations * 95) / 100];
    let p99_time = times[(iterations * 99) / 100];
    let min_time = times[0];
    let max_time = times[iterations - 1];
    
    let throughput_ops_per_sec = 1_000_000.0 / mean_time.as_micros() as f64;
    let throughput_mbps = if data_size > 0 {
        Some((data_size as f64 * throughput_ops_per_sec) / (1024.0 * 1024.0))
    } else {
        None
    };
    
    BenchmarkResult {
        test_name: test_name.to_string(),
        operation: operation.to_string(),
        data_size_bytes: data_size,
        mean_time_microseconds: mean_time.as_micros() as f64,
        median_time_microseconds: median_time.as_micros() as f64,
        p95_time_microseconds: p95_time.as_micros() as f64,
        p99_time_microseconds: p99_time.as_micros() as f64,
        min_time_microseconds: min_time.as_micros() as f64,
        max_time_microseconds: max_time.as_micros() as f64,
        throughput_ops_per_sec,
        throughput_mbps,
        memory_usage_bytes: memory_usage,
        iterations,
        warmup_time_seconds: warmup_time,
        measurement_time_seconds: measurement_time,
    }
}

// Global variable to store all benchmark results
static mut ALL_BENCHMARK_RESULTS: Option<Vec<BenchmarkResult>> = None;

fn add_benchmark_result(result: BenchmarkResult) {
    unsafe {
        if ALL_BENCHMARK_RESULTS.is_none() {
            ALL_BENCHMARK_RESULTS = Some(Vec::new());
        }
        ALL_BENCHMARK_RESULTS.as_mut().unwrap().push(result);
    }
}

fn get_all_benchmark_results() -> Vec<BenchmarkResult> {
    unsafe {
        ALL_BENCHMARK_RESULTS.clone().unwrap_or_default()
    }
}

fn benchmark_kyber_comprehensive(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber768 Comprehensive");
    
    // Key generation
    let key_gen_result = run_benchmark_with_reporting(
        "Kyber768",
        "key_generation",
        0,
        1000,
        2,
        5,
        || {
            let start = Instant::now();
            let (kyber_keys, _) = generate_crypto_identity().unwrap();
            let duration = start.elapsed();
            (duration, Some(kyber_keys.public_key.len() + kyber_keys.secret_key.len()))
        },
    );
    add_benchmark_result(key_gen_result);
    
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let (kyber_keys, _) = generate_crypto_identity().unwrap();
            black_box(kyber_keys);
        });
    });
    
    // Encapsulation
    let (kyber_keys, _) = generate_crypto_identity().unwrap();
    let encapsulation_result = run_benchmark_with_reporting(
        "Kyber768",
        "encapsulation",
        0,
        1000,
        2,
        5,
        || {
            let start = Instant::now();
            let encapsulation = encapsulate(&kyber_keys.public_key).unwrap();
            let duration = start.elapsed();
            (duration, Some(encapsulation.ciphertext.len() + encapsulation.shared_secret.len()))
        },
    );
    add_benchmark_result(encapsulation_result);
    
    group.bench_function("encapsulation", |b| {
        b.iter(|| {
            let encapsulation = encapsulate(&kyber_keys.public_key).unwrap();
            black_box(encapsulation);
        });
    });
    
    // Decapsulation
    let encapsulation = encapsulate(&kyber_keys.public_key).unwrap();
    let decapsulation_result = run_benchmark_with_reporting(
        "Kyber768",
        "decapsulation",
        0,
        1000,
        2,
        5,
        || {
            let start = Instant::now();
            let shared_secret = decapsulate(&kyber_keys.secret_key, &encapsulation.ciphertext).unwrap();
            let duration = start.elapsed();
            (duration, Some(shared_secret.len()))
        },
    );
    add_benchmark_result(decapsulation_result);
    
    group.bench_function("decapsulation", |b| {
        b.iter(|| {
            let shared_secret = decapsulate(&kyber_keys.secret_key, &encapsulation.ciphertext).unwrap();
            black_box(shared_secret);
        });
    });
    
    // Key derivation
    let key_derivation_result = run_benchmark_with_reporting(
        "Kyber768",
        "key_derivation",
        0,
        1000,
        2,
        5,
        || {
            let start = Instant::now();
            let aes_key = derive_aes_key(&encapsulation.shared_secret, b"test-context").unwrap();
            let duration = start.elapsed();
            (duration, Some(aes_key.len()))
        },
    );
    add_benchmark_result(key_derivation_result);
    
    group.bench_function("key_derivation", |b| {
        b.iter(|| {
            let aes_key = derive_aes_key(&encapsulation.shared_secret, b"test-context").unwrap();
            black_box(aes_key);
        });
    });
    
    group.finish();
}

fn benchmark_dilithium_comprehensive(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium3 Comprehensive");
    
    // Key generation
    let key_gen_result = run_benchmark_with_reporting(
        "Dilithium3",
        "key_generation",
        0,
        1000,
        2,
        5,
        || {
            let start = Instant::now();
            let (_, dilithium_keys) = generate_crypto_identity().unwrap();
            let duration = start.elapsed();
            (duration, Some(dilithium_keys.public_key.len() + dilithium_keys.secret_key.len()))
        },
    );
    add_benchmark_result(key_gen_result);
    
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let (_, dilithium_keys) = generate_crypto_identity().unwrap();
            black_box(dilithium_keys);
        });
    });
    
    // Signing with different message sizes
    for size in TEST_SIZES.iter() {
        let message = vec![42u8; *size];
        let (_, dilithium_keys) = generate_crypto_identity().unwrap();
        
        let signing_result = run_benchmark_with_reporting(
            "Dilithium3",
            &format!("signing_{}b", size),
            *size,
            1000,
            2,
            5,
            || {
                let start = Instant::now();
                let signature = sign(&message, &dilithium_keys.secret_key).unwrap();
                let duration = start.elapsed();
                (duration, Some(signature.len()))
            },
        );
        add_benchmark_result(signing_result);
        
        group.bench_function(&format!("signing_{}b", size), |b| {
            b.iter(|| {
                let signature = sign(&message, &dilithium_keys.secret_key).unwrap();
                black_box(signature);
            });
        });
    }
    
    // Verification with different message sizes
    for size in TEST_SIZES.iter() {
        let message = vec![42u8; *size];
        let (_, dilithium_keys) = generate_crypto_identity().unwrap();
        let signature = sign(&message, &dilithium_keys.secret_key).unwrap();
        
        let verification_result = run_benchmark_with_reporting(
            "Dilithium3",
            &format!("verification_{}b", size),
            *size,
            1000,
            2,
            5,
            || {
                let start = Instant::now();
                verify(&message, &signature, &dilithium_keys.public_key).unwrap();
                let duration = start.elapsed();
                (duration, None)
            },
        );
        add_benchmark_result(verification_result);
        
        group.bench_function(&format!("verification_{}b", size), |b| {
            b.iter(|| {
                verify(&message, &signature, &dilithium_keys.public_key).unwrap();
            });
        });
    }
    
    group.finish();
}

fn benchmark_aes_comprehensive(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-GCM Comprehensive");
    
    // Key generation
    let key_gen_result = run_benchmark_with_reporting(
        "AES-256-GCM",
        "key_generation",
        0,
        1000,
        2,
        5,
        || {
            let start = Instant::now();
            let key = generate_aes_key().unwrap();
            let duration = start.elapsed();
            (duration, Some(key.len()))
        },
    );
    add_benchmark_result(key_gen_result);
    
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let key = generate_aes_key().unwrap();
            black_box(key);
        });
    });
    
    // Encryption with different data sizes
    for size in TEST_SIZES.iter() {
        let data = vec![42u8; *size];
        
        let encryption_result = run_benchmark_with_reporting(
            "AES-256-GCM",
            &format!("encryption_{}b", size),
            *size,
            1000,
            2,
            5,
            || {
                let key = generate_aes_key().unwrap();
                let start = Instant::now();
                let (ciphertext, _) = encrypt_data(&data, &key).unwrap();
                let duration = start.elapsed();
                (duration, Some(ciphertext.len()))
            },
        );
        add_benchmark_result(encryption_result);
        
        group.bench_function(&format!("encryption_{}b", size), |b| {
            let key = generate_aes_key().unwrap();
            b.iter(|| {
                let (ciphertext, nonce) = encrypt_data(&data, &key).unwrap();
                black_box((ciphertext, nonce));
            });
        });
    }
    
    // Decryption with different data sizes
    for size in TEST_SIZES.iter() {
        let data = vec![42u8; *size];
        let key = generate_aes_key().unwrap();
        let (ciphertext, nonce) = encrypt_data(&data, &key).unwrap();
        
        let decryption_result = run_benchmark_with_reporting(
            "AES-256-GCM",
            &format!("decryption_{}b", size),
            *size,
            1000,
            2,
            5,
            || {
                let start = Instant::now();
                let plaintext = decrypt_data(&ciphertext, &key, &nonce).unwrap();
                let duration = start.elapsed();
                (duration, Some(plaintext.len()))
            },
        );
        add_benchmark_result(decryption_result);
        
        group.bench_function(&format!("decryption_{}b", size), |b| {
            b.iter(|| {
                let plaintext = decrypt_data(&ciphertext, &key, &nonce).unwrap();
                black_box(plaintext);
            });
        });
    }
    
    group.finish();
}

fn benchmark_file_operations_comprehensive(c: &mut Criterion) {
    let mut group = c.benchmark_group("File Operations Comprehensive");
    
    // File encryption with different sizes
    for size in TEST_SIZES.iter() {
        let temp_dir = tempdir().unwrap();
        let (_, alice_dilithium) = generate_crypto_identity().unwrap();
        let (bob_kyber, _) = generate_crypto_identity().unwrap();
        
        let test_data = vec![42u8; *size];
        let input_file = temp_dir.path().join("test.txt");
        fs::write(&input_file, &test_data).unwrap();
        
        let encryption_result = run_benchmark_with_reporting(
            "File Operations",
            &format!("encrypt_file_{}b", size),
            *size,
            100,
            2,
            5,
            || {
                let start = Instant::now();
                let result = FileProcessor::encrypt_file(
                    &input_file,
                    &bob_kyber.public_key,
                    &alice_dilithium.secret_key,
                ).unwrap();
                let duration = start.elapsed();
                (duration, Some(result.total_size()))
            },
        );
        add_benchmark_result(encryption_result);
        
        group.bench_function(&format!("encrypt_file_{}b", size), |b| {
            b.iter(|| {
                let result = FileProcessor::encrypt_file(
                    &input_file,
                    &bob_kyber.public_key,
                    &alice_dilithium.secret_key,
                ).unwrap();
                black_box(result);
            });
        });
    }
    
    // File decryption with different sizes
    for size in TEST_SIZES.iter() {
        let temp_dir = tempdir().unwrap();
        let (_, alice_dilithium) = generate_crypto_identity().unwrap();
        let (bob_kyber, _) = generate_crypto_identity().unwrap();
        
        let test_data = vec![42u8; *size];
        let input_file = temp_dir.path().join("test.txt");
        fs::write(&input_file, &test_data).unwrap();
        
        let encryption_result = FileProcessor::encrypt_file(
            &input_file,
            &bob_kyber.public_key,
            &alice_dilithium.secret_key,
        ).unwrap();
        
        let decryption_result = run_benchmark_with_reporting(
            "File Operations",
            &format!("decrypt_file_{}b", size),
            *size,
            100,
            2,
            5,
            || {
                let start = Instant::now();
                let decrypted = FileProcessor::decrypt_file(
                    &encryption_result,
                    &bob_kyber.secret_key,
                    &alice_dilithium.public_key,
                ).unwrap();
                let duration = start.elapsed();
                (duration, Some(decrypted.len()))
            },
        );
        add_benchmark_result(decryption_result);
        
        group.bench_function(&format!("decrypt_file_{}b", size), |b| {
            b.iter(|| {
                let decrypted = FileProcessor::decrypt_file(
                    &encryption_result,
                    &bob_kyber.secret_key,
                    &alice_dilithium.public_key,
                ).unwrap();
                black_box(decrypted);
            });
        });
    }
    
    group.finish();
}

criterion_group! {
    name = system_aware_benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(2))
        .measurement_time(std::time::Duration::from_secs(5));
    targets = 
        benchmark_kyber_comprehensive,
        benchmark_dilithium_comprehensive,
        benchmark_aes_comprehensive,
        benchmark_file_operations_comprehensive
}

criterion_main!(system_aware_benches);

// Print detailed metrics when benchmarks start and save comprehensive report when finished
#[ctor::ctor]
fn init() {
    println!("🔐 Enclypt 2.0 System-Aware Benchmarking Starting...");
    println!("Collecting system information and running comprehensive tests...");
}

#[ctor::dtor]
fn cleanup() {
    let system_info = collect_system_info();
    let benchmark_results = get_all_benchmark_results();
    
    if !benchmark_results.is_empty() {
        let comprehensive_report = create_comprehensive_report(system_info, benchmark_results);
        save_comprehensive_report(&comprehensive_report);
        
        println!("✅ Comprehensive benchmark report generated successfully!");
        println!("📊 Check the tests/ directory for the detailed report file.");
    }
}
