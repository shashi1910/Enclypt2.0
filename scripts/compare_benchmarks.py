#!/usr/bin/env python3
"""
Enclypt 2.0 Benchmark Comparison Tool

This script compares benchmark results across different systems and generates
comparison reports for performance analysis.
"""

import json
import csv
import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Any
import statistics
from datetime import datetime

def load_benchmark_report(report_path: Path) -> Dict[str, Any]:
    """Load a benchmark report from JSON file."""
    try:
        with open(report_path / "detailed_report.json", 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: No detailed report found in {report_path}")
        return {}
    except json.JSONDecodeError:
        print(f"Warning: Invalid JSON in {report_path}")
        return {}

def extract_system_info(report: Dict[str, Any]) -> Dict[str, str]:
    """Extract system information from a benchmark report."""
    if not report or 'system_info' not in report:
        return {}
    
    sys_info = report['system_info']
    return {
        'hostname': sys_info.get('hostname', 'Unknown'),
        'os': f"{sys_info.get('os_name', 'Unknown')} {sys_info.get('os_version', '')}",
        'cpu': sys_info.get('cpu_model', 'Unknown'),
        'cpu_cores': str(sys_info.get('cpu_cores', 0)),
        'memory_gb': f"{sys_info.get('total_memory_gb', 0):.1f}",
        'rust_version': sys_info.get('rust_version', 'Unknown'),
        'timestamp': sys_info.get('timestamp', 'Unknown')
    }

def extract_performance_data(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract performance data from benchmark results."""
    if not report or 'benchmark_results' not in report:
        return []
    
    results = []
    for benchmark in report['benchmark_results']:
        results.append({
            'test_name': benchmark.get('test_name', 'Unknown'),
            'operation': benchmark.get('operation', 'Unknown'),
            'data_size_bytes': benchmark.get('data_size_bytes', 0),
            'mean_time_microseconds': benchmark.get('mean_time_microseconds', 0),
            'median_time_microseconds': benchmark.get('median_time_microseconds', 0),
            'p95_time_microseconds': benchmark.get('p95_time_microseconds', 0),
            'p99_time_microseconds': benchmark.get('p99_time_microseconds', 0),
            'throughput_ops_per_sec': benchmark.get('throughput_ops_per_sec', 0),
            'throughput_mbps': benchmark.get('throughput_mbps', 0),
            'memory_usage_bytes': benchmark.get('memory_usage_bytes', 0)
        })
    
    return results

def find_benchmark_directories(base_path: Path) -> List[Path]:
    """Find all benchmark run directories."""
    if not base_path.exists():
        return []
    
    benchmark_dirs = []
    for item in base_path.iterdir():
        if item.is_dir() and item.name.startswith('benchmark_run_'):
            benchmark_dirs.append(item)
    
    return sorted(benchmark_dirs)

def generate_comparison_report(benchmark_dirs: List[Path], output_file: Path):
    """Generate a comprehensive comparison report."""
    
    # Collect all benchmark data
    all_data = []
    system_info = {}
    
    for benchmark_dir in benchmark_dirs:
        report = load_benchmark_report(benchmark_dir)
        if not report:
            continue
        
        # Extract system info
        sys_info = extract_system_info(report)
        system_key = f"{sys_info.get('hostname', 'Unknown')}_{sys_info.get('os', 'Unknown')}"
        system_info[system_key] = sys_info
        
        # Extract performance data
        performance_data = extract_performance_data(report)
        for data in performance_data:
            data['system_key'] = system_key
            data['benchmark_dir'] = benchmark_dir.name
            all_data.append(data)
    
    if not all_data:
        print("No benchmark data found!")
        return
    
    # Generate comparison report
    with open(output_file, 'w') as f:
        f.write("# Enclypt 2.0 Benchmark Comparison Report\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        
        # System Information
        f.write("## System Information\n\n")
        for system_key, info in system_info.items():
            f.write(f"### {system_key}\n")
            f.write(f"- **Hostname**: {info.get('hostname', 'Unknown')}\n")
            f.write(f"- **OS**: {info.get('os', 'Unknown')}\n")
            f.write(f"- **CPU**: {info.get('cpu', 'Unknown')} ({info.get('cpu_cores', '0')} cores)\n")
            f.write(f"- **Memory**: {info.get('memory_gb', '0')} GB\n")
            f.write(f"- **Rust Version**: {info.get('rust_version', 'Unknown')}\n")
            f.write(f"- **Timestamp**: {info.get('timestamp', 'Unknown')}\n\n")
        
        # Performance Comparison
        f.write("## Performance Comparison\n\n")
        
        # Group by test and operation
        test_groups = {}
        for data in all_data:
            key = f"{data['test_name']}_{data['operation']}"
            if key not in test_groups:
                test_groups[key] = []
            test_groups[key].append(data)
        
        for test_key, results in test_groups.items():
            test_name, operation = test_key.split('_', 1)
            f.write(f"### {test_name} - {operation}\n\n")
            
            # Create comparison table
            f.write("| System | Mean Time (μs) | Median (μs) | P95 (μs) | P99 (μs) | Throughput (ops/sec) |\n")
            f.write("|--------|----------------|-------------|----------|----------|---------------------|\n")
            
            for result in results:
                system_key = result['system_key']
                f.write(f"| {system_key} | {result['mean_time_microseconds']:.2f} | "
                       f"{result['median_time_microseconds']:.2f} | "
                       f"{result['p95_time_microseconds']:.2f} | "
                       f"{result['p99_time_microseconds']:.2f} | "
                       f"{result['throughput_ops_per_sec']:.0f} |\n")
            
            f.write("\n")
            
            # Calculate statistics
            mean_times = [r['mean_time_microseconds'] for r in results]
            throughputs = [r['throughput_ops_per_sec'] for r in results]
            
            if len(mean_times) > 1:
                f.write(f"- **Fastest**: {min(mean_times):.2f} μs\n")
                f.write(f"- **Slowest**: {max(mean_times):.2f} μs\n")
                f.write(f"- **Average**: {statistics.mean(mean_times):.2f} μs\n")
                f.write(f"- **Std Dev**: {statistics.stdev(mean_times):.2f} μs\n")
                f.write(f"- **Speedup**: {max(mean_times) / min(mean_times):.2f}x\n\n")
        
        # Summary statistics
        f.write("## Summary Statistics\n\n")
        
        # Overall performance comparison
        all_mean_times = [d['mean_time_microseconds'] for d in all_data]
        all_throughputs = [d['throughput_ops_per_sec'] for d in all_data]
        
        f.write(f"- **Total Tests**: {len(all_data)}\n")
        f.write(f"- **Systems Compared**: {len(system_info)}\n")
        f.write(f"- **Average Mean Time**: {statistics.mean(all_mean_times):.2f} μs\n")
        f.write(f"- **Average Throughput**: {statistics.mean(all_throughputs):.0f} ops/sec\n")
        f.write(f"- **Best Performance**: {min(all_mean_times):.2f} μs\n")
        f.write(f"- **Worst Performance**: {max(all_mean_times):.2f} μs\n\n")
        
        # Recommendations
        f.write("## Recommendations\n\n")
        f.write("1. **Performance Analysis**: Review the detailed comparisons above\n")
        f.write("2. **Bottleneck Identification**: Focus on operations with highest variance\n")
        f.write("3. **Optimization Opportunities**: Target the slowest operations\n")
        f.write("4. **Hardware Considerations**: Consider CPU and memory differences\n")
        f.write("5. **Cross-Platform Testing**: Ensure consistent performance across platforms\n\n")

def generate_csv_comparison(benchmark_dirs: List[Path], output_file: Path):
    """Generate CSV comparison data."""
    
    all_data = []
    
    for benchmark_dir in benchmark_dirs:
        report = load_benchmark_report(benchmark_dir)
        if not report:
            continue
        
        sys_info = extract_system_info(report)
        performance_data = extract_performance_data(report)
        
        for data in performance_data:
            data.update(sys_info)
            data['benchmark_dir'] = benchmark_dir.name
            all_data.append(data)
    
    if not all_data:
        print("No benchmark data found for CSV export!")
        return
    
    # Write CSV file
    with open(output_file, 'w', newline='') as f:
        fieldnames = [
            'benchmark_dir', 'hostname', 'os', 'cpu', 'cpu_cores', 'memory_gb',
            'rust_version', 'timestamp', 'test_name', 'operation', 'data_size_bytes',
            'mean_time_microseconds', 'median_time_microseconds', 'p95_time_microseconds',
            'p99_time_microseconds', 'throughput_ops_per_sec', 'throughput_mbps',
            'memory_usage_bytes'
        ]
        
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for data in all_data:
            writer.writerow(data)

def main():
    parser = argparse.ArgumentParser(
        description="Compare Enclypt 2.0 benchmark results across different systems"
    )
    parser.add_argument(
        '--baseline', 
        type=Path, 
        default=Path('tests'),
        help='Path to baseline benchmark results (default: tests/)'
    )
    parser.add_argument(
        '--current', 
        type=Path, 
        help='Path to current benchmark results (optional)'
    )
    parser.add_argument(
        '--output', 
        type=Path, 
        default=Path('tests/benchmark_comparison.md'),
        help='Output file for comparison report (default: tests/benchmark_comparison.md)'
    )
    parser.add_argument(
        '--csv', 
        type=Path, 
        default=Path('tests/benchmark_comparison.csv'),
        help='Output CSV file for data analysis (default: tests/benchmark_comparison.csv)'
    )
    
    args = parser.parse_args()
    
    # Find benchmark directories
    benchmark_dirs = []
    
    # Add baseline directories
    if args.baseline.exists():
        baseline_dirs = find_benchmark_directories(args.baseline)
        benchmark_dirs.extend(baseline_dirs)
        print(f"Found {len(baseline_dirs)} baseline benchmark directories")
    
    # Add current directories
    if args.current and args.current.exists():
        current_dirs = find_benchmark_directories(args.current)
        benchmark_dirs.extend(current_dirs)
        print(f"Found {len(current_dirs)} current benchmark directories")
    
    if not benchmark_dirs:
        print("No benchmark directories found!")
        print(f"Looked in: {args.baseline}")
        if args.current:
            print(f"         : {args.current}")
        sys.exit(1)
    
    # Ensure output directory exists
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.csv.parent.mkdir(parents=True, exist_ok=True)
    
    # Generate reports
    print(f"Generating comparison report: {args.output}")
    generate_comparison_report(benchmark_dirs, args.output)
    
    print(f"Generating CSV data: {args.csv}")
    generate_csv_comparison(benchmark_dirs, args.csv)
    
    print("Comparison completed successfully!")
    print(f"📊 Report: {args.output}")
    print(f"📈 CSV Data: {args.csv}")

if __name__ == '__main__':
    main()
