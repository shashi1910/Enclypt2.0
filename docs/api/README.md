# Enclypt 2.0 API Documentation

Welcome to the Enclypt 2.0 API documentation! This guide provides comprehensive information about using the post-quantum secure file transfer system.

## 🚀 Quick Start

### Installation

Add Enclypt 2.0 to your `Cargo.toml`:

```toml
[dependencies]
enclypt2 = "0.1.0"
```

### Basic Usage

```rust
use enclypt2::{
    crypto::{generate_crypto_identity, CryptoResult},
    file_processor::FileProcessor,
};
use std::path::Path;

fn main() -> CryptoResult<()> {
    // Generate cryptographic identities
    let (alice_kyber, alice_dilithium) = generate_crypto_identity()?;
    let (bob_kyber, _) = generate_crypto_identity()?;
    
    // Alice encrypts a file for Bob
    let result = FileProcessor::encrypt_file(
        Path::new("secret.txt"),
        &bob_kyber.public_key,
        &alice_dilithium.secret_key,
    )?;
    
    // Save encrypted file
    FileProcessor::save_encrypted_file(Path::new("secret.enc"), &result)?;
    
    Ok(())
}
```

## 📚 API Reference

### Core Modules

- **[`crypto`](crypto/index.html)** - Post-quantum cryptographic operations
- **[`file_processor`](file_processor/index.html)** - File encryption and decryption
- **[`key_manager`](key_manager/index.html)** - Key generation and management
- **[`cli`](cli/index.html)** - Command-line interface

### Key Types

- **[`KeyPair`](crypto/struct.KeyPair.html)** - Cryptographic key pair
- **[`EncryptionResult`](crypto/struct.EncryptionResult.html)** - Result of file encryption
- **[`FileMetadata`](crypto/struct.FileMetadata.html)** - File metadata information
- **[`CryptoError`](crypto/enum.CryptoError.html)** - Cryptographic error types

## 🔐 Cryptographic Algorithms

Enclypt 2.0 implements NIST-standardized post-quantum cryptographic algorithms:

| Algorithm | Purpose | Security Level | Key Size |
|-----------|---------|----------------|----------|
| **CRYSTALS-Kyber768** | Key Encapsulation | 192 bits (quantum) | 1,184B public, 2,400B secret |
| **CRYSTALS-Dilithium3** | Digital Signatures | 192 bits (quantum) | 1,952B public, 4,032B secret |
| **AES-256-GCM** | Symmetric Encryption | 256 bits (classical) | 32B key, 12B nonce |

## 📖 Examples

### File Encryption/Decryption

```rust
use enclypt2::{
    crypto::{generate_crypto_identity, CryptoResult},
    file_processor::FileProcessor,
};
use std::path::Path;

fn encrypt_and_decrypt() -> CryptoResult<()> {
    // Generate keys
    let (alice_kyber, alice_dilithium) = generate_crypto_identity()?;
    let (bob_kyber, _) = generate_crypto_identity()?;
    
    // Encrypt file
    let result = FileProcessor::encrypt_file(
        Path::new("input.txt"),
        &bob_kyber.public_key,
        &alice_dilithium.secret_key,
    )?;
    
    // Save encrypted file
    FileProcessor::save_encrypted_file(Path::new("output.enc"), &result)?;
    
    // Load and decrypt
    let loaded = FileProcessor::load_encrypted_file(Path::new("output.enc"))?;
    let decrypted = FileProcessor::decrypt_file(
        &loaded,
        &bob_kyber.secret_key,
        &alice_dilithium.public_key,
    )?;
    
    // Write decrypted file
    FileProcessor::write_file(Path::new("decrypted.txt"), &decrypted)?;
    
    Ok(())
}
```

### Key Management

```rust
use enclypt2::{
    key_manager::KeyManager,
    crypto::CryptoResult,
};

fn manage_keys() -> CryptoResult<()> {
    // Generate and save keys
    let (kyber_keys, dilithium_keys) = KeyManager::generate_and_save_keypairs(
        std::path::Path::new("./keys"),
        "alice",
    )?;
    
    // Load existing keys
    let loaded_kyber = KeyManager::load_keypair(
        std::path::Path::new("./keys"),
        "alice",
        "kyber",
    )?;
    
    // List available keys
    let key_names = KeyManager::list_keypairs(std::path::Path::new("./keys"))?;
    println!("Available keys: {:?}", key_names);
    
    Ok(())
}
```

### File Integrity Verification

```rust
use enclypt2::{
    file_processor::FileProcessor,
    crypto::CryptoResult,
};

fn verify_integrity() -> CryptoResult<()> {
    let is_valid = FileProcessor::verify_file_integrity(
        std::path::Path::new("file.enc"),
        &recipient_secret_key,
        &sender_public_key,
    )?;
    
    if is_valid {
        println!("✅ File integrity verified");
    } else {
        println!("❌ File integrity check failed");
    }
    
    Ok(())
}
```

## ⚡ Performance

Enclypt 2.0 provides excellent performance characteristics:

| Operation | Time | Throughput |
|-----------|------|------------|
| Key Generation | 68 μs | 14,700 ops/sec |
| File Encryption (1MB) | 9.4 ms | 106.7 MB/s |
| File Decryption (1MB) | 9.1 ms | 109.9 MB/s |
| Memory Overhead | 2,456 bytes per file | - |

## 🔧 Error Handling

The library provides detailed error information:

```rust
use enclypt2::crypto::{CryptoError, CryptoResult};

fn handle_errors() -> CryptoResult<()> {
    match some_operation() {
        Ok(result) => Ok(result),
        Err(CryptoError::InvalidKeySize { expected, actual }) => {
            eprintln!("Key size error: expected {}, got {}", expected, actual);
            Err(CryptoError::InvalidKeySize { expected, actual })
        }
        Err(CryptoError::FileNotFound(path)) => {
            eprintln!("File not found: {}", path.display());
            Err(CryptoError::FileNotFound(path))
        }
        Err(e) => Err(e),
    }
}
```

## 🧵 Thread Safety

All operations are thread-safe:

```rust
use std::thread;
use enclypt2::crypto::generate_crypto_identity;

fn concurrent_operations() {
    let handles: Vec<_> = (0..4).map(|_| {
        thread::spawn(|| {
            generate_crypto_identity().unwrap()
        })
    }).collect();
    
    for handle in handles {
        let (kyber, dilithium) = handle.join().unwrap();
        println!("Generated: {} + {} bytes", 
                 kyber.public_key.len(), dilithium.public_key.len());
    }
}
```

## 🛡️ Security Considerations

### Key Management
- Store secret keys securely
- Rotate keys regularly
- Validate key sizes and formats

### File Handling
- Implement secure deletion
- Use proper access controls
- Avoid information leakage

### Algorithm Security
- All algorithms are NIST-standardized
- Provides quantum-resistant security
- Maintains classical security

## 📋 Command Line Interface

Enclypt 2.0 includes a complete CLI:

```bash
# Generate keys
enclypt2 keygen --name alice

# Encrypt file
enclypt2 encrypt \
  --input secret.txt \
  --recipient-key bob_kyber_public.key \
  --sender-key alice_dilithium_secret.key \
  --output secret.enc

# Decrypt file
enclypt2 decrypt \
  --input secret.enc \
  --recipient-key bob_kyber_secret.key \
  --sender-key alice_dilithium_public.key \
  --output decrypted.txt

# Verify integrity
enclypt2 verify --input secret.enc

# List algorithms
enclypt2 algorithms
```

## 🔗 Links

- **[GitHub Repository](https://github.com/shashi1910/Enclypt2.0)**
- **[Crates.io](https://crates.io/crates/enclypt2)**
- **[Benchmark Report](https://github.com/shashi1910/Enclypt2.0/blob/main/BENCHMARK_REPORT.md)**
- **[Examples](https://github.com/shashi1910/Enclypt2.0/tree/main/examples)**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/shashi1910/Enclypt2.0/blob/main/LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](https://github.com/shashi1910/Enclypt2.0/blob/main/CONTRIBUTING.md) for guidelines.
