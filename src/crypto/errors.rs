use thiserror::Error;

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Comprehensive error types for cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Kyber key generation failed: {0}")]
    KyberKeyGeneration(String),

    #[error("Kyber encapsulation failed: {0}")]
    KyberEncapsulation(String),

    #[error("Kyber decapsulation failed: {0}")]
    KyberDecapsulation(String),

    #[error("Dilithium key generation failed: {0}")]
    DilithiumKeyGeneration(String),

    #[error("Dilithium signature generation failed: {0}")]
    DilithiumSigning(String),

    #[error("Dilithium signature verification failed: {0}")]
    DilithiumVerification(String),

    #[error("AES key derivation failed: {0}")]
    AesKeyDerivation(String),

    #[error("AES encryption failed: {0}")]
    AesEncryption(String),

    #[error("AES decryption failed: {0}")]
    AesDecryption(String),

    #[error("File integrity check failed: expected hash {expected}, got {actual}")]
    IntegrityCheckFailed {
        expected: String,
        actual: String,
    },

    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        expected: usize,
        actual: usize,
    },

    #[error("Invalid signature size: expected {expected}, got {actual}")]
    InvalidSignatureSize {
        expected: usize,
        actual: usize,
    },

    #[error("Invalid ciphertext size: expected {expected}, got {actual}")]
    InvalidCiphertextSize {
        expected: usize,
        actual: usize,
    },

    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize {
        expected: usize,
        actual: usize,
    },

    #[error("File not found: {path}")]
    FileNotFound {
        path: String,
    },

    #[error("File read error: {0}")]
    FileReadError(std::io::Error),

    #[error("File write error: {0}")]
    FileWriteError(std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(bincode::Error),

    #[error("Deserialization error: {0}")]
    DeserializationError(bincode::Error),

    #[error("Base64 encoding error: {0}")]
    Base64EncodingError(base64::DecodeError),

    #[error("Hex encoding error: {0}")]
    HexEncodingError(hex::FromHexError),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Key file corrupted: {0}")]
    KeyFileCorrupted(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Memory allocation failed: {0}")]
    MemoryAllocationError(String),

    #[error("Random number generation failed: {0}")]
    RandomGenerationError(String),

    #[error("Hash computation failed: {0}")]
    HashComputationError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl CryptoError {
    /// Check if this is a recoverable error
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            CryptoError::FileNotFound { .. }
                | CryptoError::FileReadError(_)
                | CryptoError::FileWriteError(_)
                | CryptoError::InvalidParameter(_)
        )
    }

    /// Check if this is a security-related error
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            CryptoError::IntegrityCheckFailed { .. }
                | CryptoError::DilithiumVerification(_)
                | CryptoError::InvalidKeySize { .. }
                | CryptoError::InvalidSignatureSize { .. }
                | CryptoError::InvalidCiphertextSize { .. }
        )
    }

    /// Get a user-friendly error message
    pub fn user_message(&self) -> String {
        match self {
            CryptoError::FileNotFound { path } => {
                format!("The file '{}' could not be found. Please check the path and try again.", path)
            }
            CryptoError::IntegrityCheckFailed { expected: _, actual: _ } => {
                format!("File integrity check failed. The file may have been corrupted or tampered with.")
            }
            CryptoError::DilithiumVerification(_) => {
                "Digital signature verification failed. The file may have been tampered with or the wrong key was used.".to_string()
            }
            CryptoError::InvalidKeySize { expected: _, actual: _ } => {
                format!("Invalid key size")
            }
            CryptoError::FileReadError(e) => {
                format!("Failed to read file: {}", e)
            }
            CryptoError::FileWriteError(e) => {
                format!("Failed to write file: {}", e)
            }
            _ => self.to_string(),
        }
    }

    /// Get error code for programmatic handling
    pub fn error_code(&self) -> u32 {
        match self {
            CryptoError::KyberKeyGeneration(_) => 1001,
            CryptoError::KyberEncapsulation(_) => 1002,
            CryptoError::KyberDecapsulation(_) => 1003,
            CryptoError::DilithiumKeyGeneration(_) => 2001,
            CryptoError::DilithiumSigning(_) => 2002,
            CryptoError::DilithiumVerification(_) => 2003,
            CryptoError::AesKeyDerivation(_) => 3001,
            CryptoError::AesEncryption(_) => 3002,
            CryptoError::AesDecryption(_) => 3003,
            CryptoError::IntegrityCheckFailed { .. } => 4001,
            CryptoError::InvalidKeySize { .. } => 5001,
            CryptoError::InvalidSignatureSize { .. } => 5002,
            CryptoError::InvalidCiphertextSize { .. } => 5003,
            CryptoError::InvalidNonceSize { .. } => 5004,
            CryptoError::FileNotFound { .. } => 6001,
            CryptoError::FileReadError(_) => 6002,
            CryptoError::FileWriteError(_) => 6003,
            CryptoError::SerializationError(_) => 7001,
            CryptoError::DeserializationError(_) => 7002,
            CryptoError::Base64EncodingError(_) => 8001,
            CryptoError::HexEncodingError(_) => 8002,
            CryptoError::InvalidKeyFormat(_) => 9001,
            CryptoError::KeyFileCorrupted(_) => 9002,
            CryptoError::UnsupportedAlgorithm(_) => 10001,
            CryptoError::InvalidParameter(_) => 11001,
            CryptoError::MemoryAllocationError(_) => 12001,
            CryptoError::RandomGenerationError(_) => 13001,
            CryptoError::HashComputationError(_) => 14001,
            CryptoError::InternalError(_) => 99999,
        }
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::FileReadError(err)
    }
}

impl From<bincode::Error> for CryptoError {
    fn from(err: bincode::Error) -> Self {
        CryptoError::SerializationError(err)
    }
}

impl From<base64::DecodeError> for CryptoError {
    fn from(err: base64::DecodeError) -> Self {
        CryptoError::Base64EncodingError(err)
    }
}

impl From<hex::FromHexError> for CryptoError {
    fn from(err: hex::FromHexError) -> Self {
        CryptoError::HexEncodingError(err)
    }
}

impl From<pqcrypto_traits::sign::VerificationError> for CryptoError {
    fn from(err: pqcrypto_traits::sign::VerificationError) -> Self {
        CryptoError::DilithiumVerification(format!("{:?}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(CryptoError::KyberKeyGeneration("test".to_string()).error_code(), 1001);
        assert_eq!(CryptoError::DilithiumVerification("test".to_string()).error_code(), 2003);
        assert_eq!(CryptoError::IntegrityCheckFailed {
            expected: "a".to_string(),
            actual: "b".to_string(),
        }.error_code(), 4001);
    }

    #[test]
    fn test_error_recoverability() {
        assert!(CryptoError::FileNotFound { path: "test".to_string() }.is_recoverable());
        assert!(!CryptoError::IntegrityCheckFailed {
            expected: "a".to_string(),
            actual: "b".to_string(),
        }.is_recoverable());
    }

    #[test]
    fn test_security_errors() {
        assert!(CryptoError::IntegrityCheckFailed {
            expected: "a".to_string(),
            actual: "b".to_string(),
        }.is_security_error());
        assert!(!CryptoError::FileNotFound { path: "test".to_string() }.is_security_error());
    }

    #[test]
    fn test_user_messages() {
        let msg = CryptoError::FileNotFound { path: "test.txt".to_string() }.user_message();
        assert!(msg.contains("test.txt"));
        assert!(msg.contains("could not be found"));
    }
}