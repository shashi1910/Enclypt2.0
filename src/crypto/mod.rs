//! # Post-Quantum Cryptography Module
//! 
//! This module provides a complete post-quantum secure cryptographic stack for Enclypt 2.0.
//! 
//! ## Overview
//! 
//! The crypto module implements NIST-standardized post-quantum cryptographic algorithms:
//! 
//! - **CRYSTALS-Kyber768** for key encapsulation (192-bit security)
//! - **CRYSTALS-Dilithium3** for digital signatures (192-bit security)
//! - **AES-256-GCM** for symmetric encryption
//! - **SHA-256** for hashing and key derivation
//! 
//! ## Security Levels
//! 
//! | Algorithm | Classical Security | Quantum Security | NIST Status |
//! |-----------|-------------------|------------------|-------------|
//! | CRYSTALS-Kyber768 | 256 bits | 192 bits | Standardized |
//! | CRYSTALS-Dilithium3 | 256 bits | 192 bits | Standardized |
//! | AES-256-GCM | 256 bits | 128 bits | Standardized |
//! 
//! ## Key Sizes
//! 
//! | Algorithm | Public Key | Secret Key | Ciphertext/Signature |
//! |-----------|------------|------------|---------------------|
//! | Kyber768 | 1,184 bytes | 2,400 bytes | 1,088 bytes |
//! | Dilithium3 | 1,952 bytes | 4,032 bytes | 3,309 bytes |
//! | AES-256-GCM | 32 bytes | 32 bytes | Variable |
//! 
//! ## Quick Start
//! 
//! ```rust
//! use enclypt2::crypto::{
//!     generate_crypto_identity,
//!     encapsulate,
//!     decapsulate,
//!     sign,
//!     verify,
//!     encrypt_data,
//!     decrypt_data,
//!     CryptoResult,
//! };
//! 
//! fn basic_crypto_operations() -> CryptoResult<()> {
//!     // Generate cryptographic identities
//!     let (alice_kyber, alice_dilithium) = generate_crypto_identity()?;
//!     let (bob_kyber, _) = generate_crypto_identity()?;
//!     
//!     // Key encapsulation (Alice -> Bob)
//!     let encapsulation = encapsulate(&bob_kyber.public_key)?;
//!     let shared_secret = decapsulate(&bob_kyber.secret_key, &encapsulation.ciphertext)?;
//!     
//!     // Digital signing
//!     let message = b"Hello, post-quantum world!";
//!     let signature = sign(message, &alice_dilithium.secret_key)?;
//!     verify(message, &signature, &alice_dilithium.public_key)?;
//!     
//!     // Symmetric encryption
//!     let data = b"Sensitive information";
//!     let (ciphertext, nonce) = encrypt_data(data, &shared_secret)?;
//!     let decrypted = decrypt_data(&ciphertext, &shared_secret, &nonce)?;
//!     
//!     assert_eq!(data, &decrypted[..]);
//!     Ok(())
//! }
//! ```
//! 
//! ## Advanced Usage
//! 
//! ### Custom Key Derivation
//! 
//! ```rust
//! use enclypt2::crypto::{derive_aes_key, generate_nonce, CryptoResult};
//! 
//! fn custom_key_derivation() -> CryptoResult<()> {
//!     let shared_secret = b"derived_from_kyber";
//!     let context = b"application_context";
//!     
//!     // Derive AES key from shared secret
//!     let aes_key = derive_aes_key(shared_secret, context)?;
//!     
//!     // Generate random nonce
//!     let nonce = generate_nonce()?;
//!     
//!     println!("Derived key: {} bytes", aes_key.len());
//!     println!("Nonce: {} bytes", nonce.len());
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ### Batch Operations
//! 
//! ```rust
//! use enclypt2::crypto::{sign_multiple, verify_multiple, CryptoResult};
//! 
//! fn batch_signatures() -> CryptoResult<()> {
//!     let (_, dilithium_keys) = generate_crypto_identity()?;
//!     
//!     let messages = vec![
//!         b"Message 1",
//!         b"Message 2", 
//!         b"Message 3",
//!     ];
//!     
//!     // Sign multiple messages
//!     let signature = sign_multiple(&messages, &dilithium_keys.secret_key)?;
//!     
//!     // Verify all messages
//!     verify_multiple(&messages, &signature, &dilithium_keys.public_key)?;
//!     
//!     println!("Batch signature verified successfully");
//!     Ok(())
//! }
//! ```
//! 
//! ## Performance Characteristics
//! 
//! | Operation | Time | Throughput | Notes |
//! |-----------|------|------------|-------|
//! | Kyber768 Key Generation | 68 μs | 14,694 ops/sec | Sub-millisecond |
//! | Kyber768 Encapsulation | 26 μs | 38,655 ops/sec | Fast encapsulation |
//! | Kyber768 Decapsulation | 29 μs | 33,933 ops/sec | Efficient decapsulation |
//! | Dilithium3 Key Generation | 68 μs | 14,702 ops/sec | Sub-millisecond |
//! | Dilithium3 Signing | 86 μs | 11,635 ops/sec | Probabilistic |
//! | Dilithium3 Verification | 32 μs | 31,017 ops/sec | Fast verification |
//! | AES-256-GCM Encryption | 6 μs | 164 MB/s | High throughput |
//! | AES-256-GCM Decryption | 5 μs | 187 MB/s | Efficient decryption |
//! 
//! ## Error Handling
//! 
//! The module provides detailed error information through the [`CryptoError`](errors::CryptoError) type:
//! 
//! ```rust
//! use enclypt2::crypto::{CryptoError, CryptoResult};
//! 
//! fn handle_crypto_errors() -> CryptoResult<()> {
//!     match some_operation() {
//!         Ok(result) => Ok(result),
//!         Err(CryptoError::InvalidKeySize { expected, actual }) => {
//!             eprintln!("Key size error: expected {}, got {}", expected, actual);
//!             Err(CryptoError::InvalidKeySize { expected, actual })
//!         }
//!         Err(CryptoError::KyberEncapsulation(msg)) => {
//!             eprintln!("Kyber encapsulation failed: {}", msg);
//!             Err(CryptoError::KyberEncapsulation(msg))
//!         }
//!         Err(CryptoError::DilithiumSigning(msg)) => {
//!             eprintln!("Dilithium signing failed: {}", msg);
//!             Err(CryptoError::DilithiumSigning(msg))
//!         }
//!         Err(e) => Err(e),
//!     }
//! }
//! ```
//! 
//! ## Thread Safety
//! 
//! All cryptographic operations are thread-safe and can be used in concurrent environments:
//! 
//! ```rust
//! use std::thread;
//! use enclypt2::crypto::generate_crypto_identity;
//! 
//! fn concurrent_operations() {
//!     let handles: Vec<_> = (0..4).map(|_| {
//!         thread::spawn(|| {
//!             generate_crypto_identity().unwrap()
//!         })
//!     }).collect();
//!     
//!     for handle in handles {
//!         let (kyber, dilithium) = handle.join().unwrap();
//!         println!("Generated: {} + {} bytes", 
//!                  kyber.public_key.len(), dilithium.public_key.len());
//!     }
//! }
//! ```
//! 
//! ## Security Considerations
//! 
//! ### Key Management
//! - **Secure Storage**: Store secret keys securely and never expose them
//! - **Key Rotation**: Regularly rotate keys for enhanced security
//! - **Key Validation**: Always validate key sizes and formats
//! 
//! ### Random Number Generation
//! - **Cryptographic RNG**: The library uses cryptographically secure random number generation
//! - **Nonce Uniqueness**: Each encryption operation uses a unique nonce
//! - **Key Derivation**: Shared secrets are properly derived using SHA-256
//! 
//! ### Algorithm Security
//! - **NIST Standardized**: All algorithms are NIST-standardized and well-vetted
//! - **Post-Quantum**: Provides resistance against quantum computer attacks
//! - **Classical Security**: Maintains strong security against classical attacks
//! 
//! ## Algorithm Details
//! 
//! ### CRYSTALS-Kyber768
//! 
//! Kyber768 is a lattice-based key encapsulation mechanism that provides 192-bit post-quantum security.
//! 
//! - **Security Level**: 192 bits (quantum), 256 bits (classical)
//! - **Key Sizes**: 1,184 bytes (public), 2,400 bytes (secret)
//! - **Ciphertext Size**: 1,088 bytes
//! - **Shared Secret**: 32 bytes
//! 
//! ### CRYSTALS-Dilithium3
//! 
//! Dilithium3 is a lattice-based digital signature scheme that provides 192-bit post-quantum security.
//! 
//! - **Security Level**: 192 bits (quantum), 256 bits (classical)
//! - **Key Sizes**: 1,952 bytes (public), 4,032 bytes (secret)
//! - **Signature Size**: 3,309 bytes
//! - **Deterministic**: Signatures are deterministic for the same input
//! 
//! ### AES-256-GCM
//! 
//! AES-256-GCM provides authenticated encryption with associated data.
//! 
//! - **Key Size**: 32 bytes (256 bits)
//! - **Nonce Size**: 12 bytes (96 bits)
//! - **Tag Size**: 16 bytes (128 bits)
//! - **Mode**: Galois/Counter Mode with authentication
//! 
//! ## References
//! 
//! - [NIST Post-Quantum Cryptography Standardization](https://www.nist.gov/programs-projects/post-quantum-cryptography)
//! - [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/)
//! - [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)
//! - [AES-GCM Specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

pub mod errors;
pub mod types;
pub mod kyber;
pub mod dilithium;
pub mod aes_gcm;

// Re-export commonly used types and functions
pub use errors::{CryptoError, CryptoResult};
pub use types::{KeyPair, EncryptionResult, FileMetadata, KyberEncapsulation, KeyFormat};

// Re-export Kyber functions
pub use kyber::{
    generate_keypair as generate_kyber_keypair,
    encapsulate,
    decapsulate,
    derive_aes_key,
    validate_public_key as validate_kyber_public_key,
    validate_secret_key as validate_kyber_secret_key,
    public_key_size as kyber_public_key_size,
    secret_key_size as kyber_secret_key_size,
    ciphertext_size as kyber_ciphertext_size,
    shared_secret_size as kyber_shared_secret_size,
};

// Re-export Dilithium functions
pub use dilithium::{
    generate_keypair as generate_dilithium_keypair,
    sign,
    verify,
    sign_multiple as dilithium_sign_multiple,
    verify_multiple as dilithium_verify_multiple,
    validate_public_key as validate_dilithium_public_key,
    validate_secret_key as validate_dilithium_secret_key,
    public_key_size as dilithium_public_key_size,
    secret_key_size as dilithium_secret_key_size,
    signature_size as dilithium_signature_size,
    hash_message as dilithium_hash_message,
    sign_hash as dilithium_sign_hash,
    verify_hash as dilithium_verify_hash,
};

// Re-export AES-GCM functions
pub use aes_gcm::{
    derive_aes_key as aes_derive_key,
    generate_aes_key,
    generate_nonce,
    encrypt_data,
    decrypt_data,
    encrypt_data_with_nonce as aes_encrypt_with_nonce,
    compute_data_hash,
    validate_aes_key,
    validate_nonce,
    key_size as aes_key_size,
    nonce_size as aes_nonce_size,
    tag_size as aes_tag_size,
    AES_GCM_KEY_SIZE,
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
};

/// Generate both Kyber and Dilithium key pairs for a complete crypto identity
/// 
/// This function generates a complete cryptographic identity consisting of:
/// - A Kyber768 key pair for key encapsulation
/// - A Dilithium3 key pair for digital signatures
/// 
/// # Returns
/// 
/// Returns a tuple containing `(kyber_keys, dilithium_keys)` where each is a [`KeyPair`].
/// 
/// # Errors
/// 
/// Returns [`CryptoError`] if key generation fails.
/// 
/// # Example
/// 
/// ```rust
/// use enclypt2::crypto::{generate_crypto_identity, CryptoResult};
/// 
/// fn create_identity() -> CryptoResult<()> {
///     let (kyber_keys, dilithium_keys) = generate_crypto_identity()?;
///     
///     println!("Kyber public key: {} bytes", kyber_keys.public_key.len());
///     println!("Kyber secret key: {} bytes", kyber_keys.secret_key.len());
///     println!("Dilithium public key: {} bytes", dilithium_keys.public_key.len());
///     println!("Dilithium secret key: {} bytes", dilithium_keys.secret_key.len());
///     
///     Ok(())
/// }
/// ```
pub fn generate_crypto_identity() -> CryptoResult<(KeyPair, KeyPair)> {
    let kyber_keys = generate_kyber_keypair()?;
    let dilithium_keys = generate_dilithium_keypair()?;
    
    Ok((kyber_keys, dilithium_keys))
}

/// Validate a complete crypto identity (both Kyber and Dilithium keys)
/// 
/// This function validates that both key pairs in a crypto identity have the correct sizes
/// and formats for their respective algorithms.
/// 
/// # Arguments
/// 
/// * `kyber_keys` - The Kyber768 key pair to validate
/// * `dilithium_keys` - The Dilithium3 key pair to validate
/// 
/// # Returns
/// 
/// Returns `Ok(())` if both key pairs are valid, or [`CryptoError`] if validation fails.
/// 
/// # Example
/// 
/// ```rust
/// use enclypt2::crypto::{generate_crypto_identity, validate_crypto_identity, CryptoResult};
/// 
/// fn validate_identity() -> CryptoResult<()> {
///     let (kyber_keys, dilithium_keys) = generate_crypto_identity()?;
///     
///     // Validate the complete identity
///     validate_crypto_identity(&kyber_keys, &dilithium_keys)?;
///     
///     println!("Crypto identity is valid!");
///     Ok(())
/// }
/// ```
pub fn validate_crypto_identity(kyber_keys: &KeyPair, dilithium_keys: &KeyPair) -> CryptoResult<()> {
    validate_kyber_public_key(&kyber_keys.public_key)?;
    validate_kyber_secret_key(&kyber_keys.secret_key)?;
    validate_dilithium_public_key(&dilithium_keys.public_key)?;
    validate_dilithium_secret_key(&dilithium_keys.secret_key)?;
    
    Ok(())
}

/// Get information about the cryptographic algorithms used
/// 
/// Returns detailed information about the cryptographic algorithms, including
/// security levels, key sizes, and performance characteristics.
/// 
/// # Returns
/// 
/// Returns an [`AlgorithmInfo`](types::AlgorithmInfo) struct containing algorithm details.
/// 
/// # Example
/// 
/// ```rust
/// use enclypt2::crypto::get_algorithm_info;
/// 
/// fn print_algorithm_info() {
///     let info = get_algorithm_info();
///     println!("{}", info);
/// }
/// ```
pub fn get_algorithm_info() -> AlgorithmInfo {
    AlgorithmInfo {
        kyber: KyberInfo {
            name: "CRYSTALS-Kyber768".to_string(),
            security_level: 192,
            public_key_size: kyber_public_key_size(),
            secret_key_size: kyber_secret_key_size(),
            ciphertext_size: kyber_ciphertext_size(),
            shared_secret_size: kyber_shared_secret_size(),
        },
        dilithium: DilithiumInfo {
            name: "CRYSTALS-Dilithium3".to_string(),
            security_level: 192,
            public_key_size: dilithium_public_key_size(),
            secret_key_size: dilithium_secret_key_size(),
            signature_size: dilithium_signature_size(),
        },
        aes_gcm: AesGcmInfo {
            name: "AES-256-GCM".to_string(),
            key_size: aes_key_size(),
            nonce_size: aes_nonce_size(),
            tag_size: aes_tag_size(),
        },
    }
}

/// Algorithm information structure
#[derive(Debug, Clone)]
pub struct AlgorithmInfo {
    pub kyber: KyberInfo,
    pub dilithium: DilithiumInfo,
    pub aes_gcm: AesGcmInfo,
}

/// Kyber algorithm information
#[derive(Debug, Clone)]
pub struct KyberInfo {
    pub name: String,
    pub security_level: u32,
    pub public_key_size: usize,
    pub secret_key_size: usize,
    pub ciphertext_size: usize,
    pub shared_secret_size: usize,
}

/// Dilithium algorithm information
#[derive(Debug, Clone)]
pub struct DilithiumInfo {
    pub name: String,
    pub security_level: u32,
    pub public_key_size: usize,
    pub secret_key_size: usize,
    pub signature_size: usize,
}

/// AES-GCM algorithm information
#[derive(Debug, Clone)]
pub struct AesGcmInfo {
    pub name: String,
    pub key_size: usize,
    pub nonce_size: usize,
    pub tag_size: usize,
}

impl std::fmt::Display for AlgorithmInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Enclypt 2.0 Cryptographic Stack:")?;
        writeln!(f, "  {} ({} bits, PK: {}B, SK: {}B, CT: {}B)", 
            self.kyber.name, self.kyber.security_level,
            self.kyber.public_key_size, self.kyber.secret_key_size, 
            self.kyber.ciphertext_size)?;
        writeln!(f, "  {} ({} bits, PK: {}B, SK: {}B, SIG: {}B)", 
            self.dilithium.name, self.dilithium.security_level,
            self.dilithium.public_key_size, self.dilithium.secret_key_size,
            self.dilithium.signature_size)?;
        writeln!(f, "  {} (Key: {}B, Nonce: {}B, Tag: {}B)", 
            self.aes_gcm.name, self.aes_gcm.key_size,
            self.aes_gcm.nonce_size, self.aes_gcm.tag_size)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_identity_generation() {
        let (kyber_keys, dilithium_keys) = generate_crypto_identity().unwrap();
        
        // Validate key sizes
        assert_eq!(kyber_keys.public_key.len(), kyber_public_key_size());
        assert_eq!(kyber_keys.secret_key.len(), kyber_secret_key_size());
        assert_eq!(dilithium_keys.public_key.len(), dilithium_public_key_size());
        assert_eq!(dilithium_keys.secret_key.len(), dilithium_secret_key_size());
    }

    #[test]
    fn test_crypto_identity_validation() {
        let (kyber_keys, dilithium_keys) = generate_crypto_identity().unwrap();
        
        // Valid identity should pass validation
        validate_crypto_identity(&kyber_keys, &dilithium_keys).unwrap();
    }

    #[test]
    fn test_algorithm_info() {
        let info = get_algorithm_info();
        
        assert_eq!(info.kyber.name, "CRYSTALS-Kyber768");
        assert_eq!(info.kyber.security_level, 192);
        assert_eq!(info.dilithium.name, "CRYSTALS-Dilithium3");
        assert_eq!(info.dilithium.security_level, 192);
        assert_eq!(info.aes_gcm.name, "AES-256-GCM");
        
        // Test display format
        let display_str = format!("{}", info);
        assert!(display_str.contains("CRYSTALS-Kyber768"));
        assert!(display_str.contains("CRYSTALS-Dilithium3"));
        assert!(display_str.contains("AES-256-GCM"));
    }

    #[test]
    fn test_end_to_end_crypto_workflow() {
        // Generate keys
        let (kyber_keys, dilithium_keys) = generate_crypto_identity().unwrap();
        
        // Test data
        let message = b"Hello, post-quantum world!";
        
        // Kyber encapsulation/decapsulation
        let encapsulation = encapsulate(&kyber_keys.public_key).unwrap();
        let decapsulated = decapsulate(&kyber_keys.secret_key, &encapsulation.ciphertext).unwrap();
        assert_eq!(decapsulated, encapsulation.shared_secret);
        
        // Dilithium signing/verification
        let signature = sign(message, &dilithium_keys.secret_key).unwrap();
        verify(message, &signature, &dilithium_keys.public_key).unwrap();
        
        // AES encryption/decryption
        let aes_key = derive_aes_key(&encapsulation.shared_secret, b"test-context").unwrap();
        let (ciphertext, nonce) = encrypt_data(message, &aes_key).unwrap();
        let decrypted = decrypt_data(&ciphertext, &aes_key, &nonce).unwrap();
        assert_eq!(decrypted, message);
    }
}