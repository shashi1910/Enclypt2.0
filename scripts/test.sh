#!/bin/bash
set -e

echo "🧪 Running Enclypt 2.0 tests..."

# Run all tests
cargo test --all-features

# Run benchmarks
cargo bench --all-features

echo "✅ All tests passed!"
