# Enclypt 2.0: Post-Quantum Secure File Transfer System

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Security](https://img.shields.io/badge/security-post--quantum-red?style=for-the-badge)

> 🔐 **Future-proof file encryption using NIST-standardized post-quantum cryptography**

Enclypt 2.0 is a quantum-resistant file transfer system that protects your sensitive data against both current and future threats posed by quantum computers.

## 🚀 Quick Start

```bash
# Build the project
cargo build --release --all-features

# Generate keys
./target/release/enclypt2 keygen --name alice --output ./keys/

# Encrypt a file
./target/release/enclypt2 encrypt \
  --input document.pdf \
  --recipient-key keys/alice_kyber_public.key \
  --sender-key keys/alice_dilithium_secret.key \
  --output document.pdf.enc

# Decrypt a file
./target/release/enclypt2 decrypt \
  --input document.pdf.enc \
  --recipient-key keys/alice_kyber_secret.key \
  --sender-key keys/alice_dilithium_public.key \
  --output document_decrypted.pdf
```

## 📚 Documentation

- [Quick Start Guide](QUICK_START.md)
- [API Documentation](docs/api/)
- [Development Guide](CONTRIBUTING.md)

## 🔐 Security

Uses NIST-standardized post-quantum algorithms:
- **CRYSTALS-Kyber768** for key encapsulation
- **CRYSTALS-Dilithium3** for digital signatures
- **AES-256-GCM** for symmetric encryption

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.
