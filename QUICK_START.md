# Quick Start Guide

## 🚀 Installation

1. **Install Rust**: https://rustup.rs/
2. **Clone the repository**:
   ```bash
   git clone https://github.com/shashi1910/Enclypt2.0.git
   cd Enclypt2.0
   ```
3. **Build and install**:
   ```bash
   cargo build --release
   cargo install --path .
   ```

## 🎯 Basic Usage

### Generate Keys
```bash
# Generate keys for Alice
enclypt2 keygen --name alice

# Generate keys for Bob  
enclypt2 keygen --name bob
```

### Encrypt a File
```bash
# Alice encrypts a file for Bob
enclypt2 encrypt \
  --input secret_document.txt \
  --recipient-key bob_kyber_public.key \
  --sender-key alice_dilithium_secret.key \
  --output secret_document.enc
```

### Decrypt a File
```bash
# Bob decrypts the file from Alice
enclypt2 decrypt \
  --input secret_document.enc \
  --recipient-key bob_kyber_secret.key \
  --sender-key alice_dilithium_public.key \
  --output decrypted_document.txt
```

### Run Examples
```bash
# See detailed examples
cargo run --example basic_encryption
```

## 📊 Benchmarking

Run comprehensive benchmarks with system information:
```bash
./scripts/run_system_benchmarks.sh
```

## 📚 More Information

- **Full Documentation**: [README.md](README.md)
- **Installation Guide**: [INSTALLATION.md](INSTALLATION.md)
- **Benchmarking Guide**: [docs/BENCHMARKING.md](docs/BENCHMARKING.md)
