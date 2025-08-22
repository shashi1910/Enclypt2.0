use std::path::Path;
use std::fs;
use std::io::{Read, Write};
use tracing::{info, debug, error};

use crate::crypto::{
    CryptoResult, EncryptionResult, FileMetadata,
    encapsulate, decapsulate, sign, verify, encrypt_data, decrypt_data,
    derive_aes_key, compute_data_hash,
};

/// File processor for encryption and decryption operations
pub struct FileProcessor;

impl FileProcessor {
    /// Encrypt a file using the recipient's public key and sender's secret key
    pub fn encrypt_file(
        input_path: &Path,
        recipient_public_key: &[u8],
        sender_secret_key: &[u8],
    ) -> CryptoResult<EncryptionResult> {
        let start_time = std::time::Instant::now();
        
        info!("Starting file encryption: {}", input_path.display());
        
        // Read the input file
        let file_data = Self::read_file(input_path)?;
        let original_size = file_data.len() as u64;
        
        // Calculate content hash for integrity checking
        let content_hash = compute_data_hash(&file_data);
        
        // Encapsulate with Kyber using recipient's public key to get shared secret
        let kyber_encapsulation = encapsulate(recipient_public_key)?;
        
        // Derive the AES key from the Kyber shared secret
        let aes_key = derive_aes_key(&kyber_encapsulation.shared_secret, b"file-encryption")?;
        
        // Encrypt the file data with AES-256-GCM using the derived key
        let (encrypted_data, nonce) = encrypt_data(&file_data, &aes_key)?;
        let encrypted_size = encrypted_data.len() as u64;
        
        // Create the data to be signed (encrypted data + kyber ciphertext)
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&encrypted_data);
        data_to_sign.extend_from_slice(&kyber_encapsulation.ciphertext);
        
        // Sign the data with Dilithium using sender's secret key
        let dilithium_signature = sign(&data_to_sign, sender_secret_key)?;
        
        // Create file metadata
        let filename = input_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        let metadata = FileMetadata::new(
            filename,
            original_size,
            encrypted_size,
            content_hash,
        );
        
        // Create the encryption result
        let result = EncryptionResult::new(
            encrypted_data,
            kyber_encapsulation.ciphertext,
            dilithium_signature,
            nonce,
            metadata,
        );
        
        let duration = start_time.elapsed();
        info!(
            "File encryption completed in {:?}: {} -> {} bytes",
            duration, original_size, result.total_size()
        );
        
        Ok(result)
    }
    
    /// Decrypt a file using the recipient's secret key and sender's public key
    pub fn decrypt_file(
        encryption_result: &EncryptionResult,
        recipient_secret_key: &[u8],
        sender_public_key: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let start_time = std::time::Instant::now();
        
        info!("Starting file decryption: {}", encryption_result.metadata.filename);
        
        // First, verify the Dilithium signature (fail fast)
        let mut data_to_verify = Vec::new();
        data_to_verify.extend_from_slice(&encryption_result.encrypted_data);
        data_to_verify.extend_from_slice(&encryption_result.kyber_ciphertext);
        
        verify(&data_to_verify, &encryption_result.dilithium_signature, sender_public_key)?;
        debug!("Dilithium signature verification successful");
        
        // Decapsulate the AES key using recipient's secret key
        let kyber_shared_secret = decapsulate(recipient_secret_key, &encryption_result.kyber_ciphertext)?;
        
        // Derive the AES key from the Kyber shared secret
        let aes_key = derive_aes_key(&kyber_shared_secret, b"file-encryption")?;
        
        // Decrypt the file data with AES-256-GCM
        let decrypted_data = decrypt_data(&encryption_result.encrypted_data, &aes_key, &encryption_result.nonce)?;
        
        // Verify file integrity by checking the content hash
        let computed_hash = compute_data_hash(&decrypted_data);
        if computed_hash != encryption_result.metadata.content_hash {
            return Err(crate::crypto::CryptoError::IntegrityCheckFailed {
                expected: hex::encode(&encryption_result.metadata.content_hash),
                actual: hex::encode(&computed_hash),
            });
        }
        
        let duration = start_time.elapsed();
        info!(
            "File decryption completed in {:?}: {} -> {} bytes",
            duration, encryption_result.total_size(), decrypted_data.len()
        );
        
        Ok(decrypted_data)
    }
    
    /// Save an encrypted file to disk
    pub fn save_encrypted_file(path: &Path, result: &EncryptionResult) -> CryptoResult<()> {
        info!("Saving encrypted file: {}", path.display());
        
        // Serialize the encryption result
        let serialized = bincode::serialize(result)
            .map_err(|e| crate::crypto::CryptoError::SerializationError(e))?;
        
        // Write to file
        let mut file = fs::File::create(path)
            .map_err(|e| crate::crypto::CryptoError::FileWriteError(e))?;
        
        file.write_all(&serialized)
            .map_err(|e| crate::crypto::CryptoError::FileWriteError(e))?;
        
        info!("Encrypted file saved: {} bytes", serialized.len());
        Ok(())
    }
    
    /// Load an encrypted file from disk
    pub fn load_encrypted_file(path: &Path) -> CryptoResult<EncryptionResult> {
        info!("Loading encrypted file: {}", path.display());
        
        // Read the file
        let mut file = fs::File::open(path)
            .map_err(|e| crate::crypto::CryptoError::FileReadError(e))?;
        
        let mut serialized = Vec::new();
        file.read_to_end(&mut serialized)
            .map_err(|e| crate::crypto::CryptoError::FileReadError(e))?;
        
        // Deserialize the encryption result
        let result: EncryptionResult = bincode::deserialize(&serialized)
            .map_err(|e| crate::crypto::CryptoError::DeserializationError(e))?;
        
        info!("Encrypted file loaded: {} bytes", serialized.len());
        Ok(result)
    }
    
    /// Read a file from disk
    fn read_file(path: &Path) -> CryptoResult<Vec<u8>> {
        let mut file = fs::File::open(path)
            .map_err(|e| crate::crypto::CryptoError::FileReadError(e))?;
        
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| crate::crypto::CryptoError::FileReadError(e))?;
        
        Ok(data)
    }
    
    /// Write data to a file
    pub fn write_file(path: &Path, data: &[u8]) -> CryptoResult<()> {
        let mut file = fs::File::create(path)
            .map_err(|e| crate::crypto::CryptoError::FileWriteError(e))?;
        
        file.write_all(data)
            .map_err(|e| crate::crypto::CryptoError::FileWriteError(e))?;
        
        Ok(())
    }
    
    /// Get file information without decrypting
    pub fn get_file_info(path: &Path) -> CryptoResult<FileMetadata> {
        let result = Self::load_encrypted_file(path)?;
        Ok(result.metadata)
    }
    
    /// Verify the integrity of an encrypted file
    pub fn verify_file_integrity(
        path: &Path,
        recipient_secret_key: &[u8],
        sender_public_key: &[u8],
    ) -> CryptoResult<bool> {
        info!("Verifying file integrity: {}", path.display());
        
        let result = Self::load_encrypted_file(path)?;
        
        // Try to decrypt (this will verify signature and integrity)
        match Self::decrypt_file(&result, recipient_secret_key, sender_public_key) {
            Ok(_) => {
                info!("File integrity verification successful");
                Ok(true)
            }
            Err(e) => {
                error!("File integrity verification failed: {}", e);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_file_encryption_decryption() {
        // Create a temporary test file
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = b"Hello, post-quantum file encryption!";
        temp_file.write_all(test_data).unwrap();
        
        // Generate keys
        let (kyber_keys, dilithium_keys) = crate::crypto::generate_crypto_identity().unwrap();
        
        // Encrypt the file
        let encryption_result = FileProcessor::encrypt_file(
            temp_file.path(),
            &kyber_keys.public_key,
            &dilithium_keys.secret_key,
        ).unwrap();
        
        // Decrypt the file
        let decrypted_data = FileProcessor::decrypt_file(
            &encryption_result,
            &kyber_keys.secret_key,
            &dilithium_keys.public_key,
        ).unwrap();
        
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_save_load_encrypted_file() {
        // Create test data
        let test_data = b"Test data for save/load";
        
        // Generate keys
        let (kyber_keys, dilithium_keys) = crate::crypto::generate_crypto_identity().unwrap();
        
        // Create a temporary file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(test_data).unwrap();
        
        // Encrypt the file
        let encryption_result = FileProcessor::encrypt_file(
            temp_file.path(),
            &kyber_keys.public_key,
            &dilithium_keys.secret_key,
        ).unwrap();
        
        // Save encrypted file
        let encrypted_path = NamedTempFile::new().unwrap().path().to_path_buf();
        FileProcessor::save_encrypted_file(&encrypted_path, &encryption_result).unwrap();
        
        // Load encrypted file
        let loaded_result = FileProcessor::load_encrypted_file(&encrypted_path).unwrap();
        
        // Decrypt and verify
        let decrypted_data = FileProcessor::decrypt_file(
            &loaded_result,
            &kyber_keys.secret_key,
            &dilithium_keys.public_key,
        ).unwrap();
        
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_file_integrity_verification() {
        // Create test data
        let test_data = b"Test data for integrity verification";
        
        // Generate keys
        let (kyber_keys, dilithium_keys) = crate::crypto::generate_crypto_identity().unwrap();
        
        // Create a temporary file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(test_data).unwrap();
        
        // Encrypt the file
        let encryption_result = FileProcessor::encrypt_file(
            temp_file.path(),
            &kyber_keys.public_key,
            &dilithium_keys.secret_key,
        ).unwrap();
        
        // Save encrypted file
        let encrypted_path = NamedTempFile::new().unwrap().path().to_path_buf();
        FileProcessor::save_encrypted_file(&encrypted_path, &encryption_result).unwrap();
        
        // Verify integrity
        let is_valid = FileProcessor::verify_file_integrity(
            &encrypted_path,
            &kyber_keys.secret_key,
            &dilithium_keys.public_key,
        ).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_file_info() {
        // Create test data
        let test_data = b"Test data for file info";
        
        // Generate keys
        let (kyber_keys, dilithium_keys) = crate::crypto::generate_crypto_identity().unwrap();
        
        // Create a temporary file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(test_data).unwrap();
        
        // Encrypt the file
        let encryption_result = FileProcessor::encrypt_file(
            temp_file.path(),
            &kyber_keys.public_key,
            &dilithium_keys.secret_key,
        ).unwrap();
        
        // Save encrypted file
        let encrypted_path = NamedTempFile::new().unwrap().path().to_path_buf();
        FileProcessor::save_encrypted_file(&encrypted_path, &encryption_result).unwrap();
        
        // Get file info
        let metadata = FileProcessor::get_file_info(&encrypted_path).unwrap();
        
        assert_eq!(metadata.original_size(), test_data.len() as u64);
        assert!(metadata.encrypted_size() > metadata.original_size());
        assert!(!metadata.filename().is_empty());
    }
}