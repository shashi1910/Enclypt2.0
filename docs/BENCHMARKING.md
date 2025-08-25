# Enclypt 2.0 System-Aware Benchmarking

This document describes the comprehensive benchmarking system for Enclypt 2.0, which captures detailed system information and generates comprehensive performance reports.

## Overview

The system-aware benchmarking system provides:

- **Automatic system information collection** across different platforms
- **Comprehensive performance metrics** for all cryptographic operations
- **Detailed reports** in multiple formats (JSON, TXT, CSV)
- **Cross-platform compatibility** (Linux, macOS, Windows)
- **Statistical analysis** with percentiles and throughput calculations

## Features

### 🔍 System Information Collection

The benchmark system automatically collects:

- **Operating System**: Name, version, distribution
- **Hardware**: CPU model, cores, architecture, memory
- **Software**: Rust version, Enclypt2 version
- **Environment**: Hostname, username, timestamp
- **Performance**: CPU frequency, load averages

### 📊 Performance Metrics

Each benchmark captures:

- **Timing**: Mean, median, 95th/99th percentiles, min/max
- **Throughput**: Operations per second, data throughput (MB/s)
- **Memory Usage**: Memory consumption for operations
- **Statistical Analysis**: Comprehensive statistical data

### 📁 Report Generation

Three types of reports are generated:

1. **JSON Reports** (`detailed_report.json`) - Machine-readable for analysis
2. **Text Reports** (`benchmark_report.txt`) - Human-readable summaries
3. **CSV Reports** (`benchmark_summary.csv`) - Spreadsheet-compatible data

## Quick Start

### Running Benchmarks

```bash
# Run the complete benchmark suite
./scripts/run_system_benchmarks.sh

# Or run individual benchmarks
cargo bench --bench system_aware_benchmarks
```

### Viewing Results

```bash
# View summary report
cat tests/benchmark_summary.md

# View system information
cat tests/system_info/system_details.txt

# List all benchmark runs
ls tests/benchmark_run_*/

# View detailed report for latest run
cat tests/benchmark_run_*/benchmark_report.txt
```

## Benchmark Categories

### 1. Kyber768 (Post-Quantum Key Exchange)

Tests the post-quantum key exchange algorithm:

- **Key Generation**: Creating Kyber768 key pairs
- **Encapsulation**: Generating shared secrets
- **Decapsulation**: Recovering shared secrets
- **Key Derivation**: Deriving AES keys from shared secrets

### 2. Dilithium3 (Post-Quantum Digital Signatures)

Tests the post-quantum digital signature algorithm:

- **Key Generation**: Creating Dilithium3 key pairs
- **Signing**: Signing messages of various sizes (64B to 1MB)
- **Verification**: Verifying signatures

### 3. AES-256-GCM (Symmetric Encryption)

Tests the symmetric encryption algorithm:

- **Key Generation**: Creating AES-256 keys
- **Encryption**: Encrypting data of various sizes
- **Decryption**: Decrypting data

### 4. File Operations (End-to-End)

Tests complete file encryption/decryption workflows:

- **File Encryption**: Encrypting files with post-quantum security
- **File Decryption**: Decrypting files
- **Memory Overhead**: Analyzing encryption overhead

## Test Data Sizes

The benchmarks test with the following data sizes:

- 64 bytes (small messages)
- 256 bytes (typical messages)
- 1 KB (small files)
- 4 KB (typical files)
- 16 KB (medium files)
- 64 KB (large files)
- 256 KB (very large files)
- 1 MB (huge files)

## Report Structure

### System Information Section

```
SYSTEM INFORMATION
==================
Timestamp: 2024-01-15T10:30:00Z
Hostname: my-computer.local
Username: user
OS: macOS 14.2.1
Architecture: aarch64
CPU: Apple M2 Pro (10 cores)
Memory: 16.0 GB
Rust Version: rustc 1.75.0
Enclypt2 Version: 0.1.0
```

### Performance Results Section

```
Test: Kyber768
Operation: key_generation
Data Size: 0 bytes
Mean Time: 1,234.56 μs
Median Time: 1,200.00 μs
95th Percentile: 1,500.00 μs
99th Percentile: 1,800.00 μs
Min Time: 1,000.00 μs
Max Time: 2,000.00 μs
Throughput: 810 ops/sec
Iterations: 1000
```

## Cross-Platform Testing

### Linux Systems

The benchmark system automatically detects and collects:

- Distribution information from `/etc/os-release`
- CPU details from `/proc/cpuinfo`
- Memory information from `/proc/meminfo`
- Kernel version and load averages

### macOS Systems

For macOS, the system collects:

- macOS version and build information
- CPU model using `sysctl`
- Memory size and architecture
- System performance metrics

### Windows Systems

Windows support includes:

- Windows version detection
- CPU information via `wmic`
- Memory details
- System performance data

## Analysis and Comparison

### Comparing Results Across Systems

1. **Export CSV data** from different systems
2. **Import into spreadsheet** software (Excel, Google Sheets)
3. **Create comparison charts** for performance analysis
4. **Identify performance patterns** across different hardware

### Performance Analysis

The reports help identify:

- **Bottlenecks**: Slowest operations
- **Scalability**: Performance with different data sizes
- **Memory usage**: Memory consumption patterns
- **Throughput**: Operations per second capabilities

### Security Validation

Use the reports to verify:

- **Algorithm performance** meets security requirements
- **Key generation** times are acceptable
- **Encryption/decryption** throughput is sufficient
- **Memory usage** is within acceptable limits

## Customization

### Modifying Test Parameters

Edit `benches/system_aware_benchmarks.rs` to customize:

```rust
// Change test data sizes
const TEST_SIZES: [usize; 8] = [64, 256, 1024, 4096, 16384, 65536, 262144, 1048576];

// Modify iteration counts
const ITERATIONS: usize = 1000;

// Adjust warmup and measurement times
warmup_time: 2,
measurement_time: 5,
```

### Adding New Benchmarks

To add new benchmark tests:

1. Create a new benchmark function
2. Use `run_benchmark_with_reporting()` for detailed metrics
3. Add to the criterion group
4. Update the benchmark script

### Custom Report Formats

Modify the report generation functions:

- `generate_text_report()` - Customize text format
- `generate_csv_summary()` - Modify CSV structure
- `save_test_report()` - Add new report types

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the script is executable
   ```bash
   chmod +x scripts/run_system_benchmarks.sh
   ```

2. **Missing Dependencies**: Install required tools
   ```bash
   # For memory calculation on Linux
   sudo apt-get install bc
   
   # For macOS
   brew install coreutils
   ```

3. **Benchmark Failures**: Check system resources
   ```bash
   # Monitor system resources during benchmarks
   htop
   ```

### Debug Mode

Enable verbose output:

```bash
# Run with debug information
RUST_LOG=debug cargo bench --bench system_aware_benchmarks
```

### Performance Tips

1. **Close unnecessary applications** during benchmarks
2. **Use consistent system state** across test runs
3. **Run multiple iterations** for statistical significance
4. **Monitor system temperature** for thermal throttling

## Integration with CI/CD

### Automated Benchmarking

Add to your CI pipeline:

```yaml
# GitHub Actions example
- name: Run Benchmarks
  run: |
    ./scripts/run_system_benchmarks.sh
    
- name: Upload Results
  uses: actions/upload-artifact@v3
  with:
    name: benchmark-results
    path: tests/
```

### Performance Regression Testing

Compare results against baselines:

```bash
# Compare with previous results
python scripts/compare_benchmarks.py \
  --baseline tests/baseline/ \
  --current tests/benchmark_run_*/
```

## Contributing

When adding new benchmarks:

1. **Follow the existing pattern** in `system_aware_benchmarks.rs`
2. **Include system information** collection
3. **Generate comprehensive reports**
4. **Update documentation** with new features
5. **Test across platforms** when possible

## References

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Performance Benchmarking Best Practices](https://github.com/bheisler/criterion.rs#best-practices)
