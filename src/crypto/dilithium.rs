use pqcrypto_dilithium::dilithium3::{keypair, PublicKey, SecretKey, DetachedSignature};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, DetachedSignature as SignDetachedSignature};
use sha2::{Digest, Sha256};

use super::{errors::CryptoResult, types::*};

// Dilithium3 constants
pub const DILITHIUM3_PUBLICKEYBYTES: usize = 1952;
pub const DILITHIUM3_SECRETKEYBYTES: usize = 4032;
pub const DILITHIUM3_SIGNBYTES: usize = 3309;

/// Generate a new Dilithium3 key pair
pub fn generate_keypair() -> CryptoResult<KeyPair> {
    let start_time = std::time::Instant::now();
    
    let (public_key, secret_key) = keypair();
    
    let keypair = KeyPair::new(public_key.as_bytes().to_vec(), secret_key.as_bytes().to_vec());
    
    let duration = start_time.elapsed();
    tracing::debug!("Dilithium key generation took {:?}", duration);
    
    Ok(keypair)
}

/// Sign a message using the secret key
pub fn sign(message: &[u8], secret_key: &[u8]) -> CryptoResult<Vec<u8>> {
    let start_time = std::time::Instant::now();
    
    // Validate secret key size
    if secret_key.len() != DILITHIUM3_SECRETKEYBYTES {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: DILITHIUM3_SECRETKEYBYTES,
            actual: secret_key.len(),
        });
    }
    
    // Convert to the expected type
    let sk = SecretKey::from_bytes(secret_key)
        .map_err(|e| super::errors::CryptoError::DilithiumSigning(format!("Invalid secret key: {:?}", e)))?;
    
    // Generate signature
    let signature = pqcrypto_dilithium::dilithium3::detached_sign(message, &sk);
    
    let duration = start_time.elapsed();
    tracing::debug!("Dilithium signing took {:?}", duration);
    
    Ok(signature.as_bytes().to_vec())
}

/// Verify a signature using the public key
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> CryptoResult<()> {
    let start_time = std::time::Instant::now();
    
    // Validate public key and signature sizes
    if public_key.len() != DILITHIUM3_PUBLICKEYBYTES {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: DILITHIUM3_PUBLICKEYBYTES,
            actual: public_key.len(),
        });
    }
    
    if signature.len() != DILITHIUM3_SIGNBYTES {
        return Err(super::errors::CryptoError::InvalidSignatureSize {
            expected: DILITHIUM3_SIGNBYTES,
            actual: signature.len(),
        });
    }
    
    // Convert to the expected types
    let pk = PublicKey::from_bytes(public_key)
        .map_err(|e| super::errors::CryptoError::DilithiumVerification(format!("Invalid public key: {:?}", e)))?;
    
    let sig = DetachedSignature::from_bytes(signature)
        .map_err(|e| super::errors::CryptoError::DilithiumVerification(format!("Invalid signature: {:?}", e)))?;
    
    // Verify signature
    pqcrypto_dilithium::dilithium3::verify_detached_signature(&sig, message, &pk)?;
    
    let duration = start_time.elapsed();
    tracing::debug!("Dilithium verification took {:?}", duration);
    
    Ok(())
}

/// Sign multiple concatenated messages
pub fn sign_multiple(messages: &[&[u8]], secret_key: &[u8]) -> CryptoResult<Vec<u8>> {
    let start_time = std::time::Instant::now();
    
    // Validate secret key size
    if secret_key.len() != DILITHIUM3_SECRETKEYBYTES {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: DILITHIUM3_SECRETKEYBYTES,
            actual: secret_key.len(),
        });
    }
    
    // Concatenate all messages with a separator
    let mut combined_message = Vec::new();
    for (i, message) in messages.iter().enumerate() {
        if i > 0 {
            combined_message.extend_from_slice(b"||");
        }
        combined_message.extend_from_slice(message);
    }
    
    // Sign the combined message
    let signature = sign(&combined_message, secret_key)?;
    
    let duration = start_time.elapsed();
    tracing::debug!("Dilithium multi-message signing took {:?}", duration);
    
    Ok(signature)
}

/// Verify signature for multiple concatenated messages
pub fn verify_multiple(messages: &[&[u8]], signature: &[u8], public_key: &[u8]) -> CryptoResult<()> {
    let start_time = std::time::Instant::now();
    
    // Concatenate all messages with a separator (same as in sign_multiple)
    let mut combined_message = Vec::new();
    for (i, message) in messages.iter().enumerate() {
        if i > 0 {
            combined_message.extend_from_slice(b"||");
        }
        combined_message.extend_from_slice(message);
    }
    
    // Verify the signature
    let result = verify(&combined_message, signature, public_key);
    
    let duration = start_time.elapsed();
    tracing::debug!("Dilithium multi-message verification took {:?}", duration);
    
    result
}

/// Validate a Dilithium public key
pub fn validate_public_key(public_key: &[u8]) -> CryptoResult<()> {
    if public_key.len() != DILITHIUM3_PUBLICKEYBYTES {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: DILITHIUM3_PUBLICKEYBYTES,
            actual: public_key.len(),
        });
    }
    
    // Try to parse the public key to ensure it's valid
    PublicKey::from_bytes(public_key)
        .map_err(|e| super::errors::CryptoError::InvalidParameter(format!("Invalid public key: {:?}", e)))?;
    
    Ok(())
}

/// Validate a Dilithium secret key
pub fn validate_secret_key(secret_key: &[u8]) -> CryptoResult<()> {
    if secret_key.len() != DILITHIUM3_SECRETKEYBYTES {
        return Err(super::errors::CryptoError::InvalidKeySize {
            expected: DILITHIUM3_SECRETKEYBYTES,
            actual: secret_key.len(),
        });
    }
    
    // Try to parse the secret key to ensure it's valid
    SecretKey::from_bytes(secret_key)
        .map_err(|e| super::errors::CryptoError::InvalidParameter(format!("Invalid secret key: {:?}", e)))?;
    
    Ok(())
}

/// Get the expected size of Dilithium public keys
pub fn public_key_size() -> usize {
    DILITHIUM3_PUBLICKEYBYTES
}

/// Get the expected size of Dilithium secret keys
pub fn secret_key_size() -> usize {
    DILITHIUM3_SECRETKEYBYTES
}

/// Get the expected size of Dilithium signatures
pub fn signature_size() -> usize {
    DILITHIUM3_SIGNBYTES
}

/// Create a hash of the message for signing (useful for large messages)
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Sign a message hash instead of the full message
pub fn sign_hash(message_hash: &[u8; 32], secret_key: &[u8]) -> CryptoResult<Vec<u8>> {
    sign(message_hash, secret_key)
}

/// Verify a signature against a message hash
pub fn verify_hash(message_hash: &[u8; 32], signature: &[u8], public_key: &[u8]) -> CryptoResult<()> {
    verify(message_hash, signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_key_generation() {
        let keypair = generate_keypair().unwrap();
        
        assert_eq!(keypair.public_key.len(), DILITHIUM3_PUBLICKEYBYTES);
        assert_eq!(keypair.secret_key.len(), DILITHIUM3_SECRETKEYBYTES);
    }

    #[test]
    fn test_dilithium_sign_verify() {
        let keypair = generate_keypair().unwrap();
        let message = b"Hello, post-quantum world!";
        
        let signature = sign(message, &keypair.secret_key).unwrap();
        assert_eq!(signature.len(), DILITHIUM3_SIGNBYTES);
        
        verify(message, &signature, &keypair.public_key).unwrap();
    }

    #[test]
    fn test_dilithium_wrong_key_verification() {
        let keypair1 = generate_keypair().unwrap();
        let keypair2 = generate_keypair().unwrap();
        let message = b"Test message";
        
        let signature = sign(message, &keypair1.secret_key).unwrap();
        
        // Should fail with wrong public key
        assert!(verify(message, &signature, &keypair2.public_key).is_err());
    }

    #[test]
    fn test_dilithium_tampered_message() {
        let keypair = generate_keypair().unwrap();
        let message = b"Original message";
        let tampered_message = b"Tampered message";
        
        let signature = sign(message, &keypair.secret_key).unwrap();
        
        // Should fail with tampered message
        assert!(verify(tampered_message, &signature, &keypair.public_key).is_err());
    }

    #[test]
    fn test_dilithium_multiple_messages() {
        let keypair = generate_keypair().unwrap();
        let messages = [b"Message 1" as &[u8], b"Message 2" as &[u8], b"Message 3" as &[u8]];
        
        let signature = sign_multiple(&messages, &keypair.secret_key).unwrap();
        verify_multiple(&messages, &signature, &keypair.public_key).unwrap();
    }

    #[test]
    fn test_dilithium_key_validation() {
        let keypair = generate_keypair().unwrap();
        
        // Valid keys should pass validation
        validate_public_key(&keypair.public_key).unwrap();
        validate_secret_key(&keypair.secret_key).unwrap();
        
        // Invalid key sizes should fail
        assert!(validate_public_key(&[0u8; 10]).is_err());
        assert!(validate_secret_key(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_dilithium_hash_signing() {
        let keypair = generate_keypair().unwrap();
        let message = b"Large message that we want to hash before signing";
        
        let hash = hash_message(message);
        let signature = sign_hash(&hash, &keypair.secret_key).unwrap();
        
        verify_hash(&hash, &signature, &keypair.public_key).unwrap();
    }

    #[test]
    fn test_dilithium_constants() {
        assert_eq!(public_key_size(), DILITHIUM3_PUBLICKEYBYTES);
        assert_eq!(secret_key_size(), DILITHIUM3_SECRETKEYBYTES);
        assert_eq!(signature_size(), DILITHIUM3_SIGNBYTES);
    }

    #[test]
    fn test_dilithium_empty_message() {
        let keypair = generate_keypair().unwrap();
        let message = b"";
        
        let signature = sign(message, &keypair.secret_key).unwrap();
        verify(message, &signature, &keypair.public_key).unwrap();
    }

    #[test]
    fn test_dilithium_large_message() {
        let keypair = generate_keypair().unwrap();
        let message = vec![0u8; 10000]; // 10KB message
        
        let signature = sign(&message, &keypair.secret_key).unwrap();
        verify(&message, &signature, &keypair.public_key).unwrap();
    }
}