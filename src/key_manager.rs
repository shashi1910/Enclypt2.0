use std::path::{Path, PathBuf};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use tracing::{info, debug, warn};
use base64::Engine;

use crate::crypto::{
    CryptoResult, KeyPair, KeyFormat,
    generate_kyber_keypair, generate_dilithium_keypair,
    validate_kyber_public_key, validate_kyber_secret_key,
    validate_dilithium_public_key, validate_dilithium_secret_key,
};

/// Key manager for handling key storage and management
pub struct KeyManager;

impl KeyManager {
    /// Save both Kyber and Dilithium key pairs to a directory
    pub fn save_keypairs(
        output_dir: &Path,
        name: &str,
        kyber_keypair: &KeyPair,
        dilithium_keypair: &KeyPair,
    ) -> CryptoResult<()> {
        info!("Saving key pairs for '{}' to {}", name, output_dir.display());
        
        // Create output directory if it doesn't exist
        fs::create_dir_all(output_dir)
            .map_err(|e| crate::crypto::CryptoError::FileWriteError(e))?;
        
        // Save Kyber keys
        let kyber_public_path = output_dir.join(format!("{}_kyber_public.key", name));
        let kyber_secret_path = output_dir.join(format!("{}_kyber_secret.key", name));
        
        Self::save_key(&kyber_public_path, &kyber_keypair.public_key, KeyFormat::Pem)?;
        Self::save_key(&kyber_secret_path, &kyber_keypair.secret_key, KeyFormat::Pem)?;
        
        // Save Dilithium keys
        let dilithium_public_path = output_dir.join(format!("{}_dilithium_public.key", name));
        let dilithium_secret_path = output_dir.join(format!("{}_dilithium_secret.key", name));
        
        Self::save_key(&dilithium_public_path, &dilithium_keypair.public_key, KeyFormat::Pem)?;
        Self::save_key(&dilithium_secret_path, &dilithium_keypair.secret_key, KeyFormat::Pem)?;
        
        info!("Key pairs saved successfully for '{}'", name);
        Ok(())
    }
    
    /// Load both Kyber and Dilithium key pairs from a directory
    pub fn load_keypairs(
        key_dir: &Path,
        name: &str,
    ) -> CryptoResult<(KeyPair, KeyPair)> {
        info!("Loading key pairs for '{}' from {}", name, key_dir.display());
        
        // Load Kyber keys
        let kyber_public_path = key_dir.join(format!("{}_kyber_public.key", name));
        let kyber_secret_path = key_dir.join(format!("{}_kyber_secret.key", name));
        
        let kyber_public_key = Self::load_key(&kyber_public_path)?;
        let kyber_secret_key = Self::load_key(&kyber_secret_path)?;
        
        let kyber_keypair = KeyPair::new(kyber_public_key, kyber_secret_key);
        
        // Load Dilithium keys
        let dilithium_public_path = key_dir.join(format!("{}_dilithium_public.key", name));
        let dilithium_secret_path = key_dir.join(format!("{}_dilithium_secret.key", name));
        
        let dilithium_public_key = Self::load_key(&dilithium_public_path)?;
        let dilithium_secret_key = Self::load_key(&dilithium_secret_path)?;
        
        let dilithium_keypair = KeyPair::new(dilithium_public_key, dilithium_secret_key);
        
        // Validate the loaded keys
        validate_kyber_public_key(&kyber_keypair.public_key)?;
        validate_kyber_secret_key(&kyber_keypair.secret_key)?;
        validate_dilithium_public_key(&dilithium_keypair.public_key)?;
        validate_dilithium_secret_key(&dilithium_keypair.secret_key)?;
        
        info!("Key pairs loaded successfully for '{}'", name);
        Ok((kyber_keypair, dilithium_keypair))
    }
    
    /// Generate and save new key pairs
    pub fn generate_and_save_keypairs(
        output_dir: &Path,
        name: &str,
    ) -> CryptoResult<(KeyPair, KeyPair)> {
        info!("Generating and saving new key pairs for '{}'", name);
        
        // Generate new key pairs
        let kyber_keypair = generate_kyber_keypair()?;
        let dilithium_keypair = generate_dilithium_keypair()?;
        
        // Save the key pairs
        Self::save_keypairs(output_dir, name, &kyber_keypair, &dilithium_keypair)?;
        
        Ok((kyber_keypair, dilithium_keypair))
    }
    
    /// Load a key from a file
    pub fn load_key(path: &Path) -> CryptoResult<Vec<u8>> {
        debug!("Loading key from: {}", path.display());
        
        let mut file = fs::File::open(path)
            .map_err(|e| crate::crypto::CryptoError::FileReadError(e))?;
        
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| crate::crypto::CryptoError::FileReadError(e))?;
        
        // Detect format and decode if necessary
        let key_data = Self::detect_and_decode_key_format(&data)?;
        
        Ok(key_data)
    }
    
    /// Save a key to a file
    pub fn save_key(path: &Path, key_data: &[u8], format: KeyFormat) -> CryptoResult<()> {
        debug!("Saving key to: {} in {} format", path.display(), format);
        
        // Encode the key data according to the specified format
        let encoded_data = Self::encode_key_data(key_data, format)?;
        
        // Write to file
        let mut file = fs::File::create(path)
            .map_err(|e| crate::crypto::CryptoError::FileWriteError(e))?;
        
        file.write_all(&encoded_data)
            .map_err(|e| crate::crypto::CryptoError::FileWriteError(e))?;
        
        // Set secure permissions on Unix systems
        #[cfg(unix)]
        {
            let mut perms = file.metadata()
                .map_err(|e| crate::crypto::CryptoError::FileWriteError(e))?
                .permissions();
            
            // Set read/write for owner only (0600)
            perms.set_mode(0o600);
            file.set_permissions(perms)
                .map_err(|e| crate::crypto::CryptoError::FileWriteError(e))?;
        }
        
        Ok(())
    }
    
    /// List all available key pairs in a directory
    pub fn list_keypairs(key_dir: &Path) -> CryptoResult<Vec<String>> {
        debug!("Listing key pairs in: {}", key_dir.display());
        
        if !key_dir.exists() {
            return Ok(Vec::new());
        }
        
        let mut key_names = std::collections::HashSet::new();
        
        for entry in fs::read_dir(key_dir)
            .map_err(|e| crate::crypto::CryptoError::FileReadError(e))? {
            let entry = entry
                .map_err(|e| crate::crypto::CryptoError::FileReadError(e))?;
            
            let file_name = entry.file_name();
            if let Some(name) = file_name.to_str() {
                // Extract key name from filename (e.g., "alice_kyber_public.key" -> "alice")
                if let Some(key_name) = Self::extract_key_name(name) {
                    key_names.insert(key_name.to_string());
                }
            }
        }
        
        let mut names: Vec<String> = key_names.into_iter().collect();
        names.sort();
        
        Ok(names)
    }
    
    /// Delete key pairs for a given name
    pub fn delete_keypairs(key_dir: &Path, name: &str) -> CryptoResult<()> {
        info!("Deleting key pairs for '{}' from {}", name, key_dir.display());
        
        let key_files = [
            format!("{}_kyber_public.key", name),
            format!("{}_kyber_secret.key", name),
            format!("{}_dilithium_public.key", name),
            format!("{}_dilithium_secret.key", name),
        ];
        
        for file_name in &key_files {
            let file_path = key_dir.join(file_name);
            if file_path.exists() {
                fs::remove_file(&file_path)
                    .map_err(|e| crate::crypto::CryptoError::FileWriteError(e))?;
                debug!("Deleted key file: {}", file_path.display());
            }
        }
        
        info!("Key pairs deleted successfully for '{}'", name);
        Ok(())
    }
    
    /// Validate that all required key files exist for a given name
    pub fn validate_keypair_files(key_dir: &Path, name: &str) -> CryptoResult<bool> {
        let required_files = [
            format!("{}_kyber_public.key", name),
            format!("{}_kyber_secret.key", name),
            format!("{}_dilithium_public.key", name),
            format!("{}_dilithium_secret.key", name),
        ];
        
        for file_name in &required_files {
            let file_path = key_dir.join(file_name);
            if !file_path.exists() {
                warn!("Missing key file: {}", file_path.display());
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Get the default key directory for the current user
    pub fn get_default_key_dir() -> CryptoResult<PathBuf> {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| crate::crypto::CryptoError::InternalError(
                "Could not determine home directory".to_string(),
            ))?;
        
        let key_dir = home_dir.join(".enclypt2").join("keys");
        Ok(key_dir)
    }
    
    // Private helper methods
    
    fn detect_and_decode_key_format(data: &[u8]) -> CryptoResult<Vec<u8>> {
        // Try to detect the format based on content
        let content = String::from_utf8_lossy(data);
        
        if content.starts_with("-----BEGIN") {
            // PEM format
            Self::decode_pem_key(&content)
        } else if content.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
            // Base64 format
            Self::decode_base64_key(data)
        } else {
            // Assume raw binary format
            Ok(data.to_vec())
        }
    }
    
    fn encode_key_data(key_data: &[u8], format: KeyFormat) -> CryptoResult<Vec<u8>> {
        match format {
            KeyFormat::Raw => Ok(key_data.to_vec()),
            KeyFormat::Base64 => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(key_data);
                Ok(encoded.into_bytes())
            }
            KeyFormat::Pem => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(key_data);
                let pem_content = format!(
                    "-----BEGIN ENCRYPTED KEY-----\n{}\n-----END ENCRYPTED KEY-----\n",
                    encoded
                );
                Ok(pem_content.into_bytes())
            }
        }
    }
    
    fn decode_pem_key(content: &str) -> CryptoResult<Vec<u8>> {
        // Simple PEM decoder - in production you might want to use a proper PEM library
        let lines: Vec<&str> = content.lines().collect();
        let mut base64_content = String::new();
        
        let mut in_key = false;
        for line in lines {
            if line.starts_with("-----BEGIN") {
                in_key = true;
            } else if line.starts_with("-----END") {
                break;
            } else if in_key {
                base64_content.push_str(line);
            }
        }
        
        let decoded = base64::engine::general_purpose::STANDARD.decode(&base64_content)
            .map_err(|e| crate::crypto::CryptoError::Base64EncodingError(e))?;
        
        Ok(decoded)
    }
    
    fn decode_base64_key(data: &[u8]) -> CryptoResult<Vec<u8>> {
        let content = String::from_utf8_lossy(data);
        let decoded = base64::engine::general_purpose::STANDARD.decode(content.trim())
            .map_err(|e| crate::crypto::CryptoError::Base64EncodingError(e))?;
        
        Ok(decoded)
    }
    
    fn extract_key_name(filename: &str) -> Option<&str> {
        // Extract key name from filename patterns like:
        // "alice_kyber_public.key" -> "alice"
        // "bob_dilithium_secret.key" -> "bob"
        
        if filename.ends_with(".key") {
            let name_part = &filename[..filename.len() - 4]; // Remove ".key"
            // Find the underscore before the key type (kyber/dilithium)
            if let Some(kyber_pos) = name_part.find("_kyber_") {
                return Some(&name_part[..kyber_pos]);
            } else if let Some(dilithium_pos) = name_part.find("_dilithium_") {
                return Some(&name_part[..dilithium_pos]);
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_load_keypairs() {
        let temp_dir = TempDir::new().unwrap();
        
        // Generate key pairs
        let kyber_keys = generate_kyber_keypair().unwrap();
        let dilithium_keys = generate_dilithium_keypair().unwrap();
        
        // Save key pairs
        KeyManager::save_keypairs(temp_dir.path(), "test_user", &kyber_keys, &dilithium_keys).unwrap();
        
        // Load key pairs
        let (loaded_kyber, loaded_dilithium) = KeyManager::load_keypairs(temp_dir.path(), "test_user").unwrap();
        
        // Verify keys match
        assert_eq!(loaded_kyber.public_key, kyber_keys.public_key);
        assert_eq!(loaded_kyber.secret_key, kyber_keys.secret_key);
        assert_eq!(loaded_dilithium.public_key, dilithium_keys.public_key);
        assert_eq!(loaded_dilithium.secret_key, dilithium_keys.secret_key);
    }

    #[test]
    fn test_generate_and_save_keypairs() {
        let temp_dir = TempDir::new().unwrap();
        
        // Generate and save key pairs
        let (kyber_keys, dilithium_keys) = KeyManager::generate_and_save_keypairs(temp_dir.path(), "new_user").unwrap();
        
        // Verify files were created
        assert!(temp_dir.path().join("new_user_kyber_public.key").exists());
        assert!(temp_dir.path().join("new_user_kyber_secret.key").exists());
        assert!(temp_dir.path().join("new_user_dilithium_public.key").exists());
        assert!(temp_dir.path().join("new_user_dilithium_secret.key").exists());
        
        // Verify keys are valid
        validate_kyber_public_key(&kyber_keys.public_key).unwrap();
        validate_kyber_secret_key(&kyber_keys.secret_key).unwrap();
        validate_dilithium_public_key(&dilithium_keys.public_key).unwrap();
        validate_dilithium_secret_key(&dilithium_keys.secret_key).unwrap();
    }

    #[test]
    fn test_save_load_key() {
        let temp_dir = TempDir::new().unwrap();
        let key_data = vec![1, 2, 3, 4, 5];
        let key_path = temp_dir.path().join("test.key");
        
        // Save key in different formats
        KeyManager::save_key(&key_path, &key_data, KeyFormat::Raw).unwrap();
        let loaded_raw = KeyManager::load_key(&key_path).unwrap();
        assert_eq!(loaded_raw, key_data);
        
        KeyManager::save_key(&key_path, &key_data, KeyFormat::Base64).unwrap();
        let loaded_base64 = KeyManager::load_key(&key_path).unwrap();
        assert_eq!(loaded_base64, key_data);
        
        KeyManager::save_key(&key_path, &key_data, KeyFormat::Pem).unwrap();
        let loaded_pem = KeyManager::load_key(&key_path).unwrap();
        assert_eq!(loaded_pem, key_data);
    }

    #[test]
    fn test_list_keypairs() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create some test key files
        let test_names = ["alice", "bob", "charlie"];
        
        for name in &test_names {
            let kyber_keys = generate_kyber_keypair().unwrap();
            let dilithium_keys = generate_dilithium_keypair().unwrap();
            KeyManager::save_keypairs(temp_dir.path(), name, &kyber_keys, &dilithium_keys).unwrap();
        }
        
        // List key pairs
        let key_names = KeyManager::list_keypairs(temp_dir.path()).unwrap();
        
        assert_eq!(key_names.len(), 3);
        assert!(key_names.contains(&"alice".to_string()));
        assert!(key_names.contains(&"bob".to_string()));
        assert!(key_names.contains(&"charlie".to_string()));
    }

    #[test]
    fn test_validate_keypair_files() {
        let temp_dir = TempDir::new().unwrap();
        
        // Initially no files exist
        assert!(!KeyManager::validate_keypair_files(temp_dir.path(), "test").unwrap());
        
        // Create some but not all files
        let kyber_keys = generate_kyber_keypair().unwrap();
        KeyManager::save_key(&temp_dir.path().join("test_kyber_public.key"), &kyber_keys.public_key, KeyFormat::Raw).unwrap();
        KeyManager::save_key(&temp_dir.path().join("test_kyber_secret.key"), &kyber_keys.secret_key, KeyFormat::Raw).unwrap();
        
        // Still missing Dilithium files
        assert!(!KeyManager::validate_keypair_files(temp_dir.path(), "test").unwrap());
        
        // Create all files
        let dilithium_keys = generate_dilithium_keypair().unwrap();
        KeyManager::save_key(&temp_dir.path().join("test_dilithium_public.key"), &dilithium_keys.public_key, KeyFormat::Raw).unwrap();
        KeyManager::save_key(&temp_dir.path().join("test_dilithium_secret.key"), &dilithium_keys.secret_key, KeyFormat::Raw).unwrap();
        
        // Now all files exist
        assert!(KeyManager::validate_keypair_files(temp_dir.path(), "test").unwrap());
    }

    #[test]
    fn test_delete_keypairs() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create key pairs
        let kyber_keys = generate_kyber_keypair().unwrap();
        let dilithium_keys = generate_dilithium_keypair().unwrap();
        KeyManager::save_keypairs(temp_dir.path(), "test_user", &kyber_keys, &dilithium_keys).unwrap();
        
        // Verify files exist
        assert!(temp_dir.path().join("test_user_kyber_public.key").exists());
        
        // Delete key pairs
        KeyManager::delete_keypairs(temp_dir.path(), "test_user").unwrap();
        
        // Verify files are deleted
        assert!(!temp_dir.path().join("test_user_kyber_public.key").exists());
        assert!(!temp_dir.path().join("test_user_kyber_secret.key").exists());
        assert!(!temp_dir.path().join("test_user_dilithium_public.key").exists());
        assert!(!temp_dir.path().join("test_user_dilithium_secret.key").exists());
    }
}