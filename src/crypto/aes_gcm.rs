use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

use super::errors::CryptoResult;

/// AES-256-GCM nonce size (12 bytes = 96 bits)
pub const AES_GCM_NONCE_SIZE: usize = 12;
/// AES-256-GCM key size (32 bytes = 256 bits)
pub const AES_GCM_KEY_SIZE: usize = 32;
/// AES-GCM tag size (16 bytes = 128 bits)
pub const AES_GCM_TAG_SIZE: usize = 16;

/// Derive an AES key from Kyber shared secret and additional context
pub fn derive_aes_key(kyber_shared_secret: &[u8], context: &[u8]) -> CryptoResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"Kyber-AES-Derivation");
    hasher.update(kyber_shared_secret);
    hasher.update(context);
    
    let result = hasher.finalize();
    let mut aes_key = [0u8; 32];
    aes_key.copy_from_slice(&result);
    
    Ok(aes_key)
}

/// Generate a random AES key
pub fn generate_aes_key() -> CryptoResult<[u8; 32]> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    Ok(key)
}

/// Generate a random nonce for AES-GCM
pub fn generate_nonce() -> CryptoResult<[u8; 12]> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    Ok(nonce)
}

/// Encrypt data using AES-256-GCM
pub fn encrypt_data(data: &[u8], aes_key: &[u8; 32]) -> CryptoResult<(Vec<u8>, [u8; 12])> {
    let start_time = std::time::Instant::now();
    
    // Validate key size
    if aes_key.len() != AES_GCM_KEY_SIZE {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: AES_GCM_KEY_SIZE,
            actual: aes_key.len(),
        });
    }
    
    // Generate a random nonce
    let nonce_bytes = generate_nonce()?;
    
    // Create AES-GCM cipher
    let key = Key::<Aes256Gcm>::from_slice(aes_key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);
    
    // Encrypt the data
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| super::errors::CryptoError::AesEncryption(format!("{:?}", e)))?;
    
    let duration = start_time.elapsed();
    tracing::debug!("AES-GCM encryption took {:?} for {} bytes", duration, data.len());
    
    Ok((ciphertext, nonce_bytes))
}

/// Decrypt data using AES-256-GCM
pub fn decrypt_data(ciphertext: &[u8], aes_key: &[u8; 32], nonce: &[u8; 12]) -> CryptoResult<Vec<u8>> {
    let start_time = std::time::Instant::now();
    
    // Validate key and nonce sizes
    if aes_key.len() != AES_GCM_KEY_SIZE {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: AES_GCM_KEY_SIZE,
            actual: aes_key.len(),
        });
    }
    
    if nonce.len() != AES_GCM_NONCE_SIZE {
        return Err(super::errors::CryptoError::InvalidNonceSize {
            expected: AES_GCM_NONCE_SIZE,
            actual: nonce.len(),
        });
    }
    
    // Create AES-GCM cipher
    let key = Key::<Aes256Gcm>::from_slice(aes_key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    
    // Decrypt the data
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| super::errors::CryptoError::AesDecryption(format!("{:?}", e)))?;
    
    let duration = start_time.elapsed();
    tracing::debug!("AES-GCM decryption took {:?} for {} bytes", duration, ciphertext.len());
    
    Ok(plaintext)
}

/// Encrypt data with a specific nonce (for testing or deterministic encryption)
pub fn encrypt_data_with_nonce(data: &[u8], aes_key: &[u8; 32], nonce: &[u8; 12]) -> CryptoResult<Vec<u8>> {
    let start_time = std::time::Instant::now();
    
    // Validate key and nonce sizes
    if aes_key.len() != AES_GCM_KEY_SIZE {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: AES_GCM_KEY_SIZE,
            actual: aes_key.len(),
        });
    }
    
    if nonce.len() != AES_GCM_NONCE_SIZE {
        return Err(super::errors::CryptoError::InvalidNonceSize {
            expected: AES_GCM_NONCE_SIZE,
            actual: nonce.len(),
        });
    }
    
    // Create AES-GCM cipher
    let key = Key::<Aes256Gcm>::from_slice(aes_key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    
    // Encrypt the data
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| super::errors::CryptoError::AesEncryption(format!("{:?}", e)))?;
    
    let duration = start_time.elapsed();
    tracing::debug!("AES-GCM encryption with nonce took {:?} for {} bytes", duration, data.len());
    
    Ok(ciphertext)
}

/// Compute a hash of the data for integrity checking
pub fn compute_data_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Validate AES key format and size
pub fn validate_aes_key(aes_key: &[u8]) -> CryptoResult<()> {
    if aes_key.len() != AES_GCM_KEY_SIZE {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: AES_GCM_KEY_SIZE,
            actual: aes_key.len(),
        });
    }
    
    // Check that the key is not all zeros (weak key)
    if aes_key.iter().all(|&x| x == 0) {
        return Err(super::errors::CryptoError::InvalidParameter(
            "AES key cannot be all zeros".to_string(),
        ));
    }
    
    Ok(())
}

/// Validate nonce format and size
pub fn validate_nonce(nonce: &[u8]) -> CryptoResult<()> {
    if nonce.len() != AES_GCM_NONCE_SIZE {
        return Err(super::errors::CryptoError::InvalidNonceSize {
            expected: AES_GCM_NONCE_SIZE,
            actual: nonce.len(),
        });
    }
    
    Ok(())
}

/// Get the expected size of AES-256-GCM keys
pub fn key_size() -> usize {
    AES_GCM_KEY_SIZE
}

/// Get the expected size of AES-GCM nonces
pub fn nonce_size() -> usize {
    AES_GCM_NONCE_SIZE
}

/// Get the expected size of AES-GCM authentication tags
pub fn tag_size() -> usize {
    AES_GCM_TAG_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_key_derivation() {
        let kyber_secret = [1u8; 32];
        let context1 = b"test-context-1";
        let context2 = b"test-context-2";
        
        let aes_key1 = derive_aes_key(&kyber_secret, context1).unwrap();
        let aes_key2 = derive_aes_key(&kyber_secret, context2).unwrap();
        
        // Different contexts should produce different keys
        assert_ne!(aes_key1, aes_key2);
        
        // Same context should produce same key
        let aes_key1_again = derive_aes_key(&kyber_secret, context1).unwrap();
        assert_eq!(aes_key1, aes_key1_again);
    }

    #[test]
    fn test_aes_encryption_decryption() {
        let aes_key = generate_aes_key().unwrap();
        let data = b"Hello, AES-GCM encryption!";
        
        let (ciphertext, nonce) = encrypt_data(data, &aes_key).unwrap();
        let decrypted = decrypt_data(&ciphertext, &aes_key, &nonce).unwrap();
        
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes_encryption_with_nonce() {
        let aes_key = generate_aes_key().unwrap();
        let nonce = generate_nonce().unwrap();
        let data = b"Test data for deterministic encryption";
        
        let ciphertext1 = encrypt_data_with_nonce(data, &aes_key, &nonce).unwrap();
        let ciphertext2 = encrypt_data_with_nonce(data, &aes_key, &nonce).unwrap();
        
        // Same key, nonce, and data should produce same ciphertext
        assert_eq!(ciphertext1, ciphertext2);
        
        // Decrypt should work
        let decrypted = decrypt_data(&ciphertext1, &aes_key, &nonce).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes_wrong_key_decryption() {
        let aes_key1 = generate_aes_key().unwrap();
        let aes_key2 = generate_aes_key().unwrap();
        let data = b"Test data";
        
        let (ciphertext, _nonce) = encrypt_data(data, &aes_key1).unwrap();
        
        // Should fail with wrong key
        assert!(decrypt_data(&ciphertext, &aes_key2, &_nonce).is_err());
    }

    #[test]
    fn test_aes_wrong_nonce_decryption() {
        let aes_key = generate_aes_key().unwrap();
        let data = b"Test data";
        
        let (ciphertext, nonce) = encrypt_data(data, &aes_key).unwrap();
        let wrong_nonce = generate_nonce().unwrap();
        
        // Should fail with wrong nonce
        assert!(decrypt_data(&ciphertext, &aes_key, &wrong_nonce).is_err());
    }

    #[test]
    fn test_aes_empty_data() {
        let aes_key = generate_aes_key().unwrap();
        let data = b"";
        
        let (ciphertext, nonce) = encrypt_data(data, &aes_key).unwrap();
        let decrypted = decrypt_data(&ciphertext, &aes_key, &nonce).unwrap();
        
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_aes_large_data() {
        let aes_key = generate_aes_key().unwrap();
        let data = vec![42u8; 10000]; // 10KB data
        
        let (ciphertext, nonce) = encrypt_data(&data, &aes_key).unwrap();
        let decrypted = decrypt_data(&ciphertext, &aes_key, &nonce).unwrap();
        
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_data_hash() {
        let data1 = b"Test data 1";
        let data2 = b"Test data 2";
        
        let hash1 = compute_data_hash(data1);
        let hash2 = compute_data_hash(data2);
        
        // Different data should produce different hashes
        assert_ne!(hash1, hash2);
        
        // Same data should produce same hash
        let hash1_again = compute_data_hash(data1);
        assert_eq!(hash1, hash1_again);
    }

    #[test]
    fn test_aes_key_validation() {
        let valid_key = generate_aes_key().unwrap();
        validate_aes_key(&valid_key).unwrap();
        
        // Invalid key size
        assert!(validate_aes_key(&[0u8; 16]).is_err());
        
        // All zeros key
        assert!(validate_aes_key(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_nonce_validation() {
        let valid_nonce = generate_nonce().unwrap();
        validate_nonce(&valid_nonce).unwrap();
        
        // Invalid nonce size
        assert!(validate_nonce(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_aes_constants() {
        assert_eq!(key_size(), AES_GCM_KEY_SIZE);
        assert_eq!(nonce_size(), AES_GCM_NONCE_SIZE);
        assert_eq!(tag_size(), AES_GCM_TAG_SIZE);
    }
}