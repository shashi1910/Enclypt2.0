# Enclypt 2.0 Makefile

.PHONY: help build test clean install bench

help:
	@echo "Enclypt 2.0 Development Commands"
	@echo "================================="
	@echo "  build         Build the project"
	@echo "  test          Run all tests"
	@echo "  bench         Run benchmarks"
	@echo "  clean         Clean build artifacts"
	@echo "  install       Install binaries"

build:
	cargo build --all-features

build-release:
	cargo build --release --all-features

test:
	cargo test --all-features

bench:
	cargo bench --all-features

clean:
	cargo clean

install:
	cargo install --path . --all-features

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets --all-features

check: fmt clippy test
