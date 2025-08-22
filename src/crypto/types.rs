use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Key pair containing public and secret keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl KeyPair {
    /// Create a new key pair from raw key data
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }

    /// Get the public key as a slice
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the secret key as a slice
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}

/// Result of encryption operation containing all necessary data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionResult {
    pub encrypted_data: Vec<u8>,
    pub kyber_ciphertext: Vec<u8>,
    pub dilithium_signature: Vec<u8>,
    pub nonce: [u8; 12],
    pub metadata: FileMetadata,
}

impl EncryptionResult {
    /// Create a new encryption result
    pub fn new(
        encrypted_data: Vec<u8>,
        kyber_ciphertext: Vec<u8>,
        dilithium_signature: Vec<u8>,
        nonce: [u8; 12],
        metadata: FileMetadata,
    ) -> Self {
        Self {
            encrypted_data,
            kyber_ciphertext,
            dilithium_signature,
            nonce,
            metadata,
        }
    }

    /// Get the total size of the encrypted data
    pub fn total_size(&self) -> usize {
        self.encrypted_data.len()
            + self.kyber_ciphertext.len()
            + self.dilithium_signature.len()
            + self.nonce.len()
    }
}

/// Metadata about the encrypted file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub filename: String,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub timestamp: u64,
    pub content_hash: [u8; 32],
}

impl FileMetadata {
    /// Create new file metadata
    pub fn new(filename: String, original_size: u64, encrypted_size: u64, content_hash: [u8; 32]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            filename,
            original_size,
            encrypted_size,
            timestamp,
            content_hash,
        }
    }

    /// Get the filename
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Get the original file size
    pub fn original_size(&self) -> u64 {
        self.original_size
    }

    /// Get the encrypted file size
    pub fn encrypted_size(&self) -> u64 {
        self.encrypted_size
    }

    /// Get the timestamp when the file was encrypted
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get the content hash
    pub fn content_hash(&self) -> &[u8; 32] {
        &self.content_hash
    }
}

/// Result of Kyber key encapsulation
#[derive(Debug, Clone)]
pub struct KyberEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl KyberEncapsulation {
    /// Create a new Kyber encapsulation result
    pub fn new(ciphertext: Vec<u8>, shared_secret: Vec<u8>) -> Self {
        Self {
            ciphertext,
            shared_secret,
        }
    }

    /// Get the ciphertext
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Get the shared secret
    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

/// Key format for storage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    Raw,
    Base64,
    Pem,
}

impl std::fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyFormat::Raw => write!(f, "raw"),
            KeyFormat::Base64 => write!(f, "base64"),
            KeyFormat::Pem => write!(f, "pem"),
        }
    }
}

impl std::str::FromStr for KeyFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "raw" => Ok(KeyFormat::Raw),
            "base64" => Ok(KeyFormat::Base64),
            "pem" => Ok(KeyFormat::Pem),
            _ => Err(format!("Unknown key format: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_pair_creation() {
        let public_key = vec![1, 2, 3, 4];
        let secret_key = vec![5, 6, 7, 8];
        let keypair = KeyPair::new(public_key.clone(), secret_key.clone());

        assert_eq!(keypair.public_key(), &public_key);
        assert_eq!(keypair.secret_key(), &secret_key);
    }

    #[test]
    fn test_file_metadata_creation() {
        let filename = "test.txt".to_string();
        let original_size = 1024;
        let encrypted_size = 2048;
        let content_hash = [0u8; 32];

        let metadata = FileMetadata::new(filename.clone(), original_size, encrypted_size, content_hash);

        assert_eq!(metadata.filename(), &filename);
        assert_eq!(metadata.original_size(), original_size);
        assert_eq!(metadata.encrypted_size(), encrypted_size);
        assert_eq!(metadata.content_hash(), &content_hash);
        assert!(metadata.timestamp() > 0);
    }

    #[test]
    fn test_kyber_encapsulation() {
        let ciphertext = vec![1, 2, 3];
        let shared_secret = vec![4, 5, 6];
        let encapsulation = KyberEncapsulation::new(ciphertext.clone(), shared_secret.clone());

        assert_eq!(encapsulation.ciphertext(), &ciphertext);
        assert_eq!(encapsulation.shared_secret(), &shared_secret);
    }

    #[test]
    fn test_key_format_display() {
        assert_eq!(KeyFormat::Raw.to_string(), "raw");
        assert_eq!(KeyFormat::Base64.to_string(), "base64");
        assert_eq!(KeyFormat::Pem.to_string(), "pem");
    }

    #[test]
    fn test_key_format_parsing() {
        assert_eq!("raw".parse::<KeyFormat>().unwrap(), KeyFormat::Raw);
        assert_eq!("base64".parse::<KeyFormat>().unwrap(), KeyFormat::Base64);
        assert_eq!("pem".parse::<KeyFormat>().unwrap(), KeyFormat::Pem);
        assert!("invalid".parse::<KeyFormat>().is_err());
    }
}