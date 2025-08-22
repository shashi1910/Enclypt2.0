use pqcrypto_kyber::kyber768::{keypair, PublicKey, SecretKey, Ciphertext};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey, SecretKey as KemSecretKey, Ciphertext as KemCiphertext, SharedSecret};

use sha2::{Digest, Sha256};

use super::{errors::CryptoResult, types::*};

// Kyber768 constants
pub const KYBER_PUBLICKEYBYTES: usize = 1184;
pub const KYBER_SECRETKEYBYTES: usize = 2400;
pub const KYBER_CIPHERTEXTBYTES: usize = 1088;
pub const KYBER_SSBYTES: usize = 32;

/// Generate a new Kyber768 key pair
pub fn generate_keypair() -> CryptoResult<KeyPair> {
    let start_time = std::time::Instant::now();
    
    let (public_key, secret_key) = keypair();
    
    let keypair = KeyPair::new(public_key.as_bytes().to_vec(), secret_key.as_bytes().to_vec());
    
    let duration = start_time.elapsed();
    tracing::debug!("Kyber key generation took {:?}", duration);
    
    Ok(keypair)
}

/// Encapsulate a shared secret using the recipient's public key
pub fn encapsulate(public_key: &[u8]) -> CryptoResult<KyberEncapsulation> {
    let start_time = std::time::Instant::now();
    
    // Validate public key size
    if public_key.len() != KYBER_PUBLICKEYBYTES {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: KYBER_PUBLICKEYBYTES,
            actual: public_key.len(),
        });
    }
    
    // Convert to the expected type
    let pk = PublicKey::from_bytes(public_key)
        .map_err(|e| super::errors::CryptoError::KyberEncapsulation(format!("Invalid public key: {:?}", e)))?;
    
    // Generate encapsulation
    let (shared_secret, ciphertext) = pqcrypto_kyber::kyber768::encapsulate(&pk);
    
    let encapsulation = KyberEncapsulation::new(
        ciphertext.as_bytes().to_vec(),
        shared_secret.as_bytes().to_vec(),
    );
    
    let duration = start_time.elapsed();
    tracing::debug!("Kyber encapsulation took {:?}", duration);
    
    Ok(encapsulation)
}

/// Decapsulate a shared secret using the recipient's secret key
pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    let start_time = std::time::Instant::now();
    
    // Validate key and ciphertext sizes
    if secret_key.len() != KYBER_SECRETKEYBYTES {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: KYBER_SECRETKEYBYTES,
            actual: secret_key.len(),
        });
    }
    
    if ciphertext.len() != KYBER_CIPHERTEXTBYTES {
        return Err(super::errors::CryptoError::InvalidCiphertextSize {
            expected: KYBER_CIPHERTEXTBYTES,
            actual: ciphertext.len(),
        });
    }
    
    // Convert to the expected types
    let sk = SecretKey::from_bytes(secret_key)
        .map_err(|e| super::errors::CryptoError::KyberDecapsulation(format!("Invalid secret key: {:?}", e)))?;
    
    let ct = Ciphertext::from_bytes(ciphertext)
        .map_err(|e| super::errors::CryptoError::KyberDecapsulation(format!("Invalid ciphertext: {:?}", e)))?;
    
    // Decapsulate the shared secret
    let shared_secret = pqcrypto_kyber::kyber768::decapsulate(&ct, &sk);
    
    let duration = start_time.elapsed();
    tracing::debug!("Kyber decapsulation took {:?}", duration);
    
    Ok(shared_secret.as_bytes().to_vec())
}

/// Generate a random AES key using Kyber shared secret and additional context
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

/// Validate a Kyber public key
pub fn validate_public_key(public_key: &[u8]) -> CryptoResult<()> {
    if public_key.len() != KYBER_PUBLICKEYBYTES {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: KYBER_PUBLICKEYBYTES,
            actual: public_key.len(),
        });
    }
    
    // Try to parse the public key to ensure it's valid
    PublicKey::from_bytes(public_key)
        .map_err(|e| super::errors::CryptoError::InvalidParameter(format!("Invalid public key: {:?}", e)))?;
    
    Ok(())
}

/// Validate a Kyber secret key
pub fn validate_secret_key(secret_key: &[u8]) -> CryptoResult<()> {
    if secret_key.len() != KYBER_SECRETKEYBYTES {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: KYBER_SECRETKEYBYTES,
            actual: secret_key.len(),
        });
    }
    
    // Try to parse the secret key to ensure it's valid
    SecretKey::from_bytes(secret_key)
        .map_err(|e| super::errors::CryptoError::InvalidParameter(format!("Invalid secret key: {:?}", e)))?;
    
    Ok(())
}

/// Get the expected size of Kyber public keys
pub fn public_key_size() -> usize {
    KYBER_PUBLICKEYBYTES
}

/// Get the expected size of Kyber secret keys
pub fn secret_key_size() -> usize {
    KYBER_SECRETKEYBYTES
}

/// Get the expected size of Kyber ciphertexts
pub fn ciphertext_size() -> usize {
    KYBER_CIPHERTEXTBYTES
}

/// Get the expected size of Kyber shared secrets
pub fn shared_secret_size() -> usize {
    KYBER_SSBYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_key_generation() {
        let keypair = generate_keypair().unwrap();
        
        assert_eq!(keypair.public_key.len(), KYBER_PUBLICKEYBYTES);
        assert_eq!(keypair.secret_key.len(), KYBER_SECRETKEYBYTES);
    }

    #[test]
    fn test_kyber_encapsulation_decapsulation() {
        let keypair = generate_keypair().unwrap();
        let encapsulation = encapsulate(&keypair.public_key).unwrap();
        
        assert_eq!(encapsulation.ciphertext.len(), KYBER_CIPHERTEXTBYTES);
        assert_eq!(encapsulation.shared_secret.len(), KYBER_SSBYTES);
        
        let decapsulated = decapsulate(&keypair.secret_key, &encapsulation.ciphertext).unwrap();
        assert_eq!(decapsulated, encapsulation.shared_secret);
    }

    #[test]
    fn test_kyber_key_validation() {
        let keypair = generate_keypair().unwrap();
        
        // Valid keys should pass validation
        validate_public_key(&keypair.public_key).unwrap();
        validate_secret_key(&keypair.secret_key).unwrap();
        
        // Invalid key sizes should fail
        assert!(validate_public_key(&[0u8; 10]).is_err());
        assert!(validate_secret_key(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_aes_key_derivation() {
        let keypair = generate_keypair().unwrap();
        let encapsulation = encapsulate(&keypair.public_key).unwrap();
        
        let context1 = b"test-context-1";
        let context2 = b"test-context-2";
        
        let aes_key1 = derive_aes_key(&encapsulation.shared_secret, context1).unwrap();
        let aes_key2 = derive_aes_key(&encapsulation.shared_secret, context2).unwrap();
        
        // Different contexts should produce different keys
        assert_ne!(aes_key1, aes_key2);
        
        // Same context should produce same key
        let aes_key1_again = derive_aes_key(&encapsulation.shared_secret, context1).unwrap();
        assert_eq!(aes_key1, aes_key1_again);
    }

    #[test]
    fn test_kyber_constants() {
        assert_eq!(public_key_size(), KYBER_PUBLICKEYBYTES);
        assert_eq!(secret_key_size(), KYBER_SECRETKEYBYTES);
        assert_eq!(ciphertext_size(), KYBER_CIPHERTEXTBYTES);
        assert_eq!(shared_secret_size(), KYBER_SSBYTES);
    }
}