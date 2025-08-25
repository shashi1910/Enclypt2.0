# Contributing to Enclypt 2.0

Thank you for your interest in contributing to Enclypt 2.0! 🚀

## 🛠️ Development Setup

1. **Install Rust 1.70+**: https://rustup.rs/
2. **Clone the repository**:
   ```bash
   git clone https://github.com/shashi1910/Enclypt2.0.git
   cd Enclypt2.0
   ```
3. **Install development tools**:
   ```bash
   make setup
   ```
4. **Run tests**:
   ```bash
   make test
   ```

## 📝 Code Style

- Use `cargo fmt` for code formatting
- Use `cargo clippy` for linting
- Write comprehensive tests for new functionality
- Follow Rust naming conventions
- Document public APIs

## 🔄 Pull Request Process

1. **Fork the repository**
2. **Create a feature branch**:
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Add tests** for new functionality
5. **Run the test suite**:
   ```bash
   cargo test
   cargo clippy
   cargo fmt
   ```
6. **Submit a pull request**

## 🧪 Testing

### Running Tests
```bash
# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Running Benchmarks
```bash
# Run performance benchmarks
cargo bench

# Run system-aware benchmarks
./scripts/run_system_benchmarks.sh
```

## 📚 Documentation

- Update documentation for any new features
- Add examples in the `examples/` directory
- Update README.md if needed
- Follow the existing documentation style

## 🔒 Security

- All cryptographic code must be thoroughly tested
- Security-related changes require additional review
- Follow cryptographic best practices
- No hardcoded keys or secrets

## 🎯 Areas for Contribution

- **Performance improvements**
- **Additional cryptographic algorithms**
- **Better error handling**
- **Cross-platform compatibility**
- **Documentation improvements**
- **Testing and benchmarking**

## 📞 Questions?

Feel free to open an issue for questions or discussions about contributions.

---

**Thank you for contributing to Enclypt 2.0! 🔐**
