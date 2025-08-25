#!/usr/bin/env python3
"""
Parse the latest Enclypt2 benchmark TXT report into a CSV file.
- Input: tests/enclypt2_benchmark_report_*.txt (latest)
- Output: tests/enclypt2_benchmark_results_*.csv
"""

import re
import sys
from pathlib import Path
from datetime import datetime

REPORT_GLOB = "enclypt2_benchmark_report_*.txt"
SUMMARY_HEADER = "PERFORMANCE SUMMARY TABLE"
TABLE_HEADER = "Test | Operation | Data Size | Mean (μs) | Throughput (ops/sec) | Throughput (MB/s)"


def find_latest_report(tests_dir: Path) -> Path:
    reports = sorted(tests_dir.glob(REPORT_GLOB))
    if not reports:
        print("No report files found.")
        sys.exit(1)
    return reports[-1]


def extract_table_lines(report_text: str) -> list[str]:
    lines = report_text.splitlines()
    try:
        start_idx = lines.index(SUMMARY_HEADER)
    except ValueError:
        print("Summary header not found in report.")
        sys.exit(1)

    # Find the table header after the summary header
    for idx in range(start_idx + 1, len(lines)):
        if lines[idx].strip() == TABLE_HEADER:
            header_idx = idx
            break
    else:
        print("Table header not found in report.")
        sys.exit(1)

    # Table separator line is next, then rows until blank
    rows = []
    for idx in range(header_idx + 2, len(lines)):
        line = lines[idx].strip()
        if not line:
            break
        rows.append(line)
    return rows


def parse_row(line: str) -> list[str]:
    # Split by pipe, strip whitespace
    parts = [p.strip() for p in line.split("|")]
    # Expect 6 columns
    if len(parts) != 6:
        # Sometimes there can be extra pipes in names; try to recombine
        # Keep first 2 and last 3, merge the middle
        if len(parts) > 6:
            merged = [parts[0], parts[1], " ".join(parts[2:-3]), parts[-3], parts[-2], parts[-1]]
            parts = [p.strip() for p in merged]
        else:
            # Pad to 6
            parts += [""] * (6 - len(parts))
    return parts


def write_csv(rows: list[list[str]], out_path: Path):
    with out_path.open("w", encoding="utf-8") as f:
        f.write("Test,Operation,Data_Size,Mean_us,Throughput_ops_per_sec,Throughput_MBps\n")
        for r in rows:
            # Normalize units: remove commas and spaces
            normalized = [
                r[0],
                r[1],
                r[2],
                r[3].replace(",", "").replace(" ", ""),
                r[4].replace(",", "").replace(" ", ""),
                r[5].replace(",", "").replace(" ", ""),
            ]
            f.write(",".join(normalized) + "\n")


def main():
    tests_dir = Path("tests")
    tests_dir.mkdir(parents=True, exist_ok=True)

    latest = find_latest_report(tests_dir)
    text = latest.read_text(encoding="utf-8")

    rows_txt = extract_table_lines(text)
    rows = [parse_row(line) for line in rows_txt]

    # Derive timestamp from file name if present
    ts_match = re.search(r"enclypt2_benchmark_report_(\d{8}_\d{6})\\.txt$", latest.name)
    ts = ts_match.group(1) if ts_match else datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = tests_dir / f"enclypt2_benchmark_results_{ts}.csv"

    write_csv(rows, out_path)

    print(f"CSV written: {out_path}")


if __name__ == "__main__":
    main()
