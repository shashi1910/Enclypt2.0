#!/bin/bash
set -e

echo "🔨 Building Enclypt 2.0..."

# Clean previous build
cargo clean

# Build with all features
cargo build --all-features

# Build release version
cargo build --release --all-features

echo "✅ Build completed successfully!"
