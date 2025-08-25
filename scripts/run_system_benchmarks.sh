#!/bin/bash

# Enclypt 2.0 System-Aware Benchmark Runner
# This script runs comprehensive benchmarks and generates detailed reports

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to collect system information
collect_system_info() {
    print_status "Collecting system information..."
    
    # Create system info directory
    mkdir -p tests/system_info
    
    # Get basic system info
    echo "=== System Information ===" > tests/system_info/system_details.txt
    echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> tests/system_info/system_details.txt
    echo "Hostname: $(hostname)" >> tests/system_info/system_details.txt
    echo "Username: $USER" >> tests/system_info/system_details.txt
    echo "" >> tests/system_info/system_details.txt
    
    # OS Information
    echo "=== Operating System ===" >> tests/system_info/system_details.txt
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "OS: Linux" >> tests/system_info/system_details.txt
        if [ -f /etc/os-release ]; then
            echo "Distribution: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)" >> tests/system_info/system_details.txt
        fi
        echo "Kernel: $(uname -r)" >> tests/system_info/system_details.txt
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "OS: macOS" >> tests/system_info/system_details.txt
        echo "Version: $(sw_vers -productVersion)" >> tests/system_info/system_details.txt
        echo "Build: $(sw_vers -buildVersion)" >> tests/system_info/system_details.txt
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        echo "OS: Windows" >> tests/system_info/system_details.txt
        echo "Version: $(ver)" >> tests/system_info/system_details.txt
    fi
    echo "" >> tests/system_info/system_details.txt
    
    # CPU Information
    echo "=== CPU Information ===" >> tests/system_info/system_details.txt
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "CPU Model: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)" >> tests/system_info/system_details.txt
        echo "CPU Cores: $(nproc)" >> tests/system_info/system_details.txt
        echo "CPU Architecture: $(uname -m)" >> tests/system_info/system_details.txt
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "CPU Model: $(sysctl -n machdep.cpu.brand_string)" >> tests/system_info/system_details.txt
        echo "CPU Cores: $(sysctl -n hw.ncpu)" >> tests/system_info/system_details.txt
        echo "CPU Architecture: $(uname -m)" >> tests/system_info/system_details.txt
    fi
    echo "" >> tests/system_info/system_details.txt
    
    # Memory Information
    echo "=== Memory Information ===" >> tests/system_info/system_details.txt
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        total_mem=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        total_mem_gb=$(echo "scale=2; $total_mem/1024/1024" | bc -l)
        echo "Total Memory: ${total_mem_gb} GB" >> tests/system_info/system_details.txt
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        total_mem=$(sysctl -n hw.memsize)
        total_mem_gb=$(echo "scale=2; $total_mem/1024/1024/1024" | bc -l)
        echo "Total Memory: ${total_mem_gb} GB" >> tests/system_info/system_details.txt
    fi
    echo "" >> tests/system_info/system_details.txt
    
    # Rust Information
    echo "=== Rust Information ===" >> tests/system_info/system_details.txt
    if command -v rustc &> /dev/null; then
        echo "Rust Version: $(rustc --version)" >> tests/system_info/system_details.txt
        echo "Cargo Version: $(cargo --version)" >> tests/system_info/system_details.txt
    else
        echo "Rust not found" >> tests/system_info/system_details.txt
    fi
    echo "" >> tests/system_info/system_details.txt
    
    # Enclypt2 Information
    echo "=== Enclypt2 Information ===" >> tests/system_info/system_details.txt
    if [ -f "Cargo.toml" ]; then
        version=$(grep '^version = ' Cargo.toml | cut -d'"' -f2)
        echo "Version: $version" >> tests/system_info/system_details.txt
    fi
    echo "Build Date: $(date)" >> tests/system_info/system_details.txt
    echo "Git Commit: $(git rev-parse HEAD 2>/dev/null || echo 'Not a git repository')" >> tests/system_info/system_details.txt
    echo "" >> tests/system_info/system_details.txt
    
    # Performance Information
    echo "=== Performance Information ===" >> tests/system_info/system_details.txt
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "CPU Frequency: $(grep 'cpu MHz' /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs) MHz" >> tests/system_info/system_details.txt
        echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')" >> tests/system_info/system_details.txt
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "CPU Frequency: $(sysctl -n hw.cpufrequency | awk '{print $1/1000000}') MHz" >> tests/system_info/system_details.txt
        echo "Load Average: $(uptime | awk -F'load averages:' '{print $2}')" >> tests/system_info/system_details.txt
    fi
    echo "" >> tests/system_info/system_details.txt
    
    print_success "System information collected and saved to tests/system_info/system_details.txt"
}

# Function to run benchmarks
run_benchmarks() {
    print_status "Running system-aware benchmarks..."
    
    # Create benchmark results directory
    mkdir -p tests/benchmark_results
    
    # Run the complete system-aware benchmark suite
    print_status "Running comprehensive benchmark suite..."
    cargo bench --bench system_aware_benchmarks 2>&1 | tee tests/benchmark_results/complete_benchmark.log
    
    print_success "All benchmarks completed successfully"
}

# Function to generate summary report
generate_summary_report() {
    print_status "Generating summary report..."
    
    # Wait a moment for the benchmark report to be generated
    sleep 2
    
    # Find the latest benchmark report
    latest_report=$(find tests -name "enclypt2_benchmark_report_*.txt" -type f | sort | tail -1)
    
    if [ -n "$latest_report" ]; then
        print_success "Comprehensive benchmark report found: $latest_report"
        print_status "Report contents preview:"
        echo ""
        head -50 "$latest_report"
        echo ""
        print_status "Full report available at: $latest_report"
    else
        print_warning "No benchmark report found. Check if benchmarks completed successfully."
    fi
}

# Function to clean up temporary files
cleanup() {
    print_status "Cleaning up temporary files..."
    
    # Remove temporary benchmark files
    find . -name "*.tmp" -delete 2>/dev/null || true
    find . -name "*.temp" -delete 2>/dev/null || true
    
    print_success "Cleanup completed"
}

# Main execution
main() {
    echo "🔐 Enclypt 2.0 System-Aware Benchmark Runner"
    echo "============================================="
    echo ""
    
    # Check if we're in the right directory
    if [ ! -f "Cargo.toml" ]; then
        print_error "Cargo.toml not found. Please run this script from the project root directory."
        exit 1
    fi
    
    # Check if Rust is installed
    if ! command -v cargo &> /dev/null; then
        print_error "Cargo not found. Please install Rust first."
        exit 1
    fi
    
    # Create necessary directories
    mkdir -p tests/system_info
    mkdir -p tests/benchmark_results
    
    # Run the benchmark process
    collect_system_info
    run_benchmarks
    generate_summary_report
    cleanup
    
    echo ""
    print_success "Benchmark process completed successfully!"
    echo ""
    echo "📊 Reports generated:"
    echo "  - System information: tests/system_info/system_details.txt"
    echo "  - Comprehensive benchmark report: tests/enclypt2_benchmark_report_*.txt"
    echo ""
    echo "🔍 To view results:"
    echo "  - cat tests/enclypt2_benchmark_report_*.txt"
    echo "  - ls tests/enclypt2_benchmark_report_*.txt"
}

# Run main function
main "$@"
