//! Enclypt 2.0 - Post-Quantum Secure File Transfer System
//! 
//! This library provides a complete post-quantum secure file transfer system using:
//! - CRYSTALS-Kyber768 for key encapsulation (192-bit security)
//! - CRYSTALS-Dilithium3 for digital signatures (192-bit security)
//! - AES-256-GCM for symmetric encryption
//! - SHA-256 for hashing and key derivation
//! 
//! ## Features
//! 
//! - **Post-quantum security**: Uses NIST-standardized algorithms resistant to quantum attacks
//! - **End-to-end encryption**: Files are encrypted on sender and decrypted only by recipient
//! - **Digital signatures**: Every file is signed for authenticity verification
//! - **High performance**: Optimized for large file processing
//! - **Cross-platform**: Works on Windows, macOS, and Linux
//! 
//! ## Quick Start
//! 
//! ```rust,no_run
//! use enclypt2::crypto::{generate_crypto_identity, EncryptionResult};
//! use enclypt2::file_processor::FileProcessor;
//! use std::path::Path;
//! # use enclypt2::CryptoResult;
//! 
//! # fn main() -> CryptoResult<()> {
//! // Generate key pairs
//! let (kyber_keys, dilithium_keys) = generate_crypto_identity()?;
//! 
//! // Encrypt a file
//! let result = FileProcessor::encrypt_file(
//!     Path::new("input.txt"),
//!     &kyber_keys.public_key,
//!     &dilithium_keys.secret_key,
//! )?;
//! 
//! // Decrypt the file
//! let decrypted = FileProcessor::decrypt_file(
//!     &result,
//!     &kyber_keys.secret_key,
//!     &dilithium_keys.public_key,
//! )?;
//! # Ok(())
//! # }
//! ```

pub mod crypto;
pub mod file_processor;
pub mod key_manager;
pub mod cli;

// Re-export commonly used types and functions
pub use crypto::{
    CryptoError, CryptoResult, KeyPair, EncryptionResult, FileMetadata,
    generate_crypto_identity, validate_crypto_identity, get_algorithm_info,
};

pub use file_processor::FileProcessor;
pub use key_manager::KeyManager;

// Re-export CLI types for binary usage
pub use cli::{Cli, Commands, handle_cli};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = "Enclypt 2.0";

/// Library description
pub const DESCRIPTION: &str = "Post-Quantum Secure File Transfer System";

/// Get library information
pub fn get_library_info() -> LibraryInfo {
    LibraryInfo {
        name: NAME.to_string(),
        version: VERSION.to_string(),
        description: DESCRIPTION.to_string(),
    }
}

/// Library information
#[derive(Debug, Clone)]
pub struct LibraryInfo {
    pub name: String,
    pub version: String,
    pub description: String,
}

impl std::fmt::Display for LibraryInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} v{}", self.name, self.version)?;
        writeln!(f, "{}", self.description)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_info() {
        let info = get_library_info();
        assert_eq!(info.name, "Enclypt 2.0");
        assert!(!info.version.is_empty());
        assert_eq!(info.description, "Post-Quantum Secure File Transfer System");
    }

    #[test]
    fn test_end_to_end_workflow() {
        // Generate keys
        let (kyber_keys, dilithium_keys) = generate_crypto_identity().unwrap();
        
        // Test data
        let test_data = b"Hello, post-quantum world!";
        
        // Create a temporary file
        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("test.txt");
        let output_path = temp_dir.path().join("test.enc");
        let decrypted_path = temp_dir.path().join("test_decrypted.txt");
        
        // Write test data
        std::fs::write(&input_path, test_data).unwrap();
        
        // Encrypt
        let result = FileProcessor::encrypt_file(
            &input_path,
            &kyber_keys.public_key,
            &dilithium_keys.secret_key,
        ).unwrap();
        
        // Save encrypted file
        FileProcessor::save_encrypted_file(&output_path, &result).unwrap();
        
        // Load and decrypt
        let loaded_result = FileProcessor::load_encrypted_file(&output_path).unwrap();
        let decrypted = FileProcessor::decrypt_file(
            &loaded_result,
            &kyber_keys.secret_key,
            &dilithium_keys.public_key,
        ).unwrap();
        
        // Verify
        assert_eq!(decrypted, test_data);
        
        // Write decrypted file
        FileProcessor::write_file(&decrypted_path, &decrypted).unwrap();
        
        // Verify file contents
        let read_data = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(read_data, test_data);
    }
}