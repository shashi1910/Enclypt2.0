//! Post-quantum cryptography module for Enclypt 2.0
//! 
//! This module provides a complete post-quantum secure cryptographic stack:
//! - CRYSTALS-Kyber768 for key encapsulation (192-bit security)
//! - CRYSTALS-Dilithium3 for digital signatures (192-bit security)
//! - AES-256-GCM for symmetric encryption
//! - SHA-256 for hashing and key derivation

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
pub fn generate_crypto_identity() -> CryptoResult<(KeyPair, KeyPair)> {
    let kyber_keys = generate_kyber_keypair()?;
    let dilithium_keys = generate_dilithium_keypair()?;
    
    Ok((kyber_keys, dilithium_keys))
}

/// Validate a complete crypto identity (both Kyber and Dilithium keys)
pub fn validate_crypto_identity(kyber_keys: &KeyPair, dilithium_keys: &KeyPair) -> CryptoResult<()> {
    validate_kyber_public_key(&kyber_keys.public_key)?;
    validate_kyber_secret_key(&kyber_keys.secret_key)?;
    validate_dilithium_public_key(&dilithium_keys.public_key)?;
    validate_dilithium_secret_key(&dilithium_keys.secret_key)?;
    
    Ok(())
}

/// Get information about the cryptographic algorithms used
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
        aes: AesInfo {
            name: "AES-256-GCM".to_string(),
            key_size: aes_key_size(),
            nonce_size: aes_nonce_size(),
            tag_size: aes_tag_size(),
        },
    }
}

/// Information about the Kyber algorithm
#[derive(Debug, Clone)]
pub struct KyberInfo {
    pub name: String,
    pub security_level: u32,
    pub public_key_size: usize,
    pub secret_key_size: usize,
    pub ciphertext_size: usize,
    pub shared_secret_size: usize,
}

/// Information about the Dilithium algorithm
#[derive(Debug, Clone)]
pub struct DilithiumInfo {
    pub name: String,
    pub security_level: u32,
    pub public_key_size: usize,
    pub secret_key_size: usize,
    pub signature_size: usize,
}

/// Information about the AES algorithm
#[derive(Debug, Clone)]
pub struct AesInfo {
    pub name: String,
    pub key_size: usize,
    pub nonce_size: usize,
    pub tag_size: usize,
}

/// Complete algorithm information
#[derive(Debug, Clone)]
pub struct AlgorithmInfo {
    pub kyber: KyberInfo,
    pub dilithium: DilithiumInfo,
    pub aes: AesInfo,
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
            self.aes.name, self.aes.key_size, self.aes.nonce_size, self.aes.tag_size)?;
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
        assert_eq!(info.aes.name, "AES-256-GCM");
        
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