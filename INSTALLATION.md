# Enclypt 2.0 - Installation Guide

## 🚀 Quick Installation

### Prerequisites
- **Rust**: Install Rust from [https://rustup.rs/](https://rustup.rs/)
- **Git**: For cloning the repository

### Installation Steps

1. **Clone the Repository**
   ```bash
   git clone https://github.com/shashi1910/Enclypt2.0.git
   cd Enclypt2.0
   ```

2. **Install Enclypt 2.0**
   ```bash
   cargo install --path .
   ```

3. **Add to PATH** (if not already added)
   ```bash
   # For macOS/Linux
   export PATH="$HOME/.cargo/bin:$PATH"
   
   # For Windows (PowerShell)
   $env:PATH += ";$env:USERPROFILE\.cargo\bin"
   ```

4. **Verify Installation**
   ```bash
   enclypt2 --help
   ```

## 🔧 Troubleshooting

### "Command not found: enclypt2"

If you get this error, the PATH is not set up correctly:

**macOS/Linux:**
```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**Windows:**
```powershell
# Add to system PATH or use full path
$env:USERPROFILE\.cargo\bin\enclypt2.exe --help
```

### Alternative: Run Directly

If PATH setup is problematic, you can run the tool directly:

```bash
# From the project directory
cargo run --bin enclypt2 -- --help

# Or use the full path
~/.cargo/bin/enclypt2 --help
```

## 📦 Building from Source

If you prefer to build from source without installing:

```bash
# Clone and build
git clone https://github.com/shashi1910/Enclypt2.0.git
cd Enclypt2.0
cargo build --release

# Run the binary
./target/release/enclypt2 --help
```

## 🧪 Testing the Installation

After installation, test the system:

```bash
# 1. Generate test keys
enclypt2 keygen --name testuser

# 2. Check algorithms
enclypt2 algorithms

# 3. List keys
enclypt2 list-keys

# 4. Run the complete example
cargo run --example basic_encryption
```

## 📋 System Requirements

- **OS**: macOS, Linux, Windows
- **Architecture**: x86_64, ARM64
- **Memory**: 50MB minimum
- **Storage**: 10MB for installation

## 🔐 Security Note

Enclypt 2.0 uses post-quantum cryptographic algorithms:
- **CRYSTALS-Kyber768**: 192-bit security
- **CRYSTALS-Dilithium3**: 192-bit security
- **AES-256-GCM**: 256-bit security

The system is production-ready and suitable for securing sensitive data.

---

**🔐 Enclypt 2.0 - Post-quantum secure file transfer system**
