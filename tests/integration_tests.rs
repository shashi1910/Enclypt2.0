//! Integration tests for Enclypt 2.0

use enclypt2::{
    crypto::{generate_crypto_identity, get_algorithm_info},
    file_processor::FileProcessor,
    key_manager::KeyManager,
};
use tempfile::tempdir;
use std::fs;

#[test]
fn test_end_to_end_encryption_decryption() {
    // Create temporary directories
    let temp_dir = tempdir().unwrap();
    let key_dir = temp_dir.path().join("keys");
    let data_dir = temp_dir.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();

    // Generate key pairs
    let (alice_kyber, alice_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "alice").unwrap();
    let (bob_kyber, bob_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "bob").unwrap();

    // Create test data
    let test_data = b"This is a test message for end-to-end encryption and decryption.";
    let input_file = data_dir.join("test.txt");
    fs::write(&input_file, test_data).unwrap();

    // Encrypt file
    let encrypted_file = data_dir.join("test.enc");
    let encryption_result = FileProcessor::encrypt_file(
        &input_file,
        &bob_kyber.public_key,
        &alice_dilithium.secret_key,
    ).unwrap();

    FileProcessor::save_encrypted_file(&encrypted_file, &encryption_result).unwrap();

    // Decrypt file
    let decrypted_file = data_dir.join("test_decrypted.txt");
    let loaded_result = FileProcessor::load_encrypted_file(&encrypted_file).unwrap();
    
    let decrypted_data = FileProcessor::decrypt_file(
        &loaded_result,
        &bob_kyber.secret_key,
        &alice_dilithium.public_key,
    ).unwrap();

    FileProcessor::write_file(&decrypted_file, &decrypted_data).unwrap();

    // Verify
    let read_data = fs::read(&decrypted_file).unwrap();
    assert_eq!(read_data, test_data);
}

#[test]
fn test_large_file_encryption() {
    // Create temporary directories
    let temp_dir = tempdir().unwrap();
    let key_dir = temp_dir.path().join("keys");
    let data_dir = temp_dir.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();

    // Generate key pairs
    let (alice_kyber, alice_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "alice").unwrap();
    let (bob_kyber, bob_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "bob").unwrap();

    // Create large test data (1MB)
    let test_data = vec![42u8; 1024 * 1024];
    let input_file = data_dir.join("large_test.bin");
    fs::write(&input_file, &test_data).unwrap();

    // Encrypt file
    let encrypted_file = data_dir.join("large_test.enc");
    let encryption_result = FileProcessor::encrypt_file(
        &input_file,
        &bob_kyber.public_key,
        &alice_dilithium.secret_key,
    ).unwrap();

    FileProcessor::save_encrypted_file(&encrypted_file, &encryption_result).unwrap();

    // Decrypt file
    let decrypted_file = data_dir.join("large_test_decrypted.bin");
    let loaded_result = FileProcessor::load_encrypted_file(&encrypted_file).unwrap();
    
    let decrypted_data = FileProcessor::decrypt_file(
        &loaded_result,
        &bob_kyber.secret_key,
        &alice_dilithium.public_key,
    ).unwrap();

    FileProcessor::write_file(&decrypted_file, &decrypted_data).unwrap();

    // Verify
    let read_data = fs::read(&decrypted_file).unwrap();
    assert_eq!(read_data, test_data);
}

#[test]
fn test_file_integrity_verification() {
    // Create temporary directories
    let temp_dir = tempdir().unwrap();
    let key_dir = temp_dir.path().join("keys");
    let data_dir = temp_dir.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();

    // Generate key pairs
    let (alice_kyber, alice_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "alice").unwrap();
    let (bob_kyber, bob_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "bob").unwrap();

    // Create test data
    let test_data = b"Test data for integrity verification";
    let input_file = data_dir.join("integrity_test.txt");
    fs::write(&input_file, test_data).unwrap();

    // Encrypt file
    let encrypted_file = data_dir.join("integrity_test.enc");
    let encryption_result = FileProcessor::encrypt_file(
        &input_file,
        &bob_kyber.public_key,
        &alice_dilithium.secret_key,
    ).unwrap();

    FileProcessor::save_encrypted_file(&encrypted_file, &encryption_result).unwrap();

    // Verify integrity
    let is_valid = FileProcessor::verify_file_integrity(
        &encrypted_file,
        &bob_kyber.secret_key,
        &alice_dilithium.public_key,
    ).unwrap();

    assert!(is_valid);
}

#[test]
fn test_wrong_key_decryption() {
    // Create temporary directories
    let temp_dir = tempdir().unwrap();
    let key_dir = temp_dir.path().join("keys");
    let data_dir = temp_dir.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();

    // Generate key pairs for three users
    let (alice_kyber, alice_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "alice").unwrap();
    let (bob_kyber, bob_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "bob").unwrap();
    let (charlie_kyber, charlie_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "charlie").unwrap();

    // Create test data
    let test_data = b"Secret message for Bob";
    let input_file = data_dir.join("secret.txt");
    fs::write(&input_file, test_data).unwrap();

    // Alice encrypts for Bob
    let encrypted_file = data_dir.join("secret.enc");
    let encryption_result = FileProcessor::encrypt_file(
        &input_file,
        &bob_kyber.public_key,
        &alice_dilithium.secret_key,
    ).unwrap();

    FileProcessor::save_encrypted_file(&encrypted_file, &encryption_result).unwrap();

    // Charlie tries to decrypt (should fail)
    let loaded_result = FileProcessor::load_encrypted_file(&encrypted_file).unwrap();
    
    let result = FileProcessor::decrypt_file(
        &loaded_result,
        &charlie_kyber.secret_key,  // Wrong key
        &alice_dilithium.public_key,
    );

    assert!(result.is_err());
}

#[test]
fn test_key_management() {
    // Create temporary directory
    let temp_dir = tempdir().unwrap();
    let key_dir = temp_dir.path().join("keys");

    // Generate keys for multiple users
    let users = ["alice", "bob", "charlie", "diana"];
    
    for user in &users {
        KeyManager::generate_and_save_keypairs(&key_dir, user).unwrap();
    }

    // List keys
    let key_names = KeyManager::list_keypairs(&key_dir).unwrap();
    assert_eq!(key_names.len(), users.len());
    
    for user in &users {
        assert!(key_names.contains(&user.to_string()));
    }

    // Validate key files exist
    for user in &users {
        let exists = KeyManager::validate_keypair_files(&key_dir, user).unwrap();
        assert!(exists);
    }

    // Delete a key pair
    KeyManager::delete_keypairs(&key_dir, "charlie").unwrap();
    
    // Verify it's deleted
    let exists = KeyManager::validate_keypair_files(&key_dir, "charlie").unwrap();
    assert!(!exists);
    
    // List keys again
    let key_names_after = KeyManager::list_keypairs(&key_dir).unwrap();
    assert_eq!(key_names_after.len(), users.len() - 1);
    assert!(!key_names_after.contains(&"charlie".to_string()));
}

#[test]
fn test_file_metadata() {
    // Create temporary directories
    let temp_dir = tempdir().unwrap();
    let key_dir = temp_dir.path().join("keys");
    let data_dir = temp_dir.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();

    // Generate key pairs
    let (alice_kyber, alice_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "alice").unwrap();
    let (bob_kyber, bob_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "bob").unwrap();

    // Create test data
    let test_data = b"Test data for metadata verification";
    let input_file = data_dir.join("metadata_test.txt");
    fs::write(&input_file, test_data).unwrap();

    // Encrypt file
    let encrypted_file = data_dir.join("metadata_test.enc");
    let encryption_result = FileProcessor::encrypt_file(
        &input_file,
        &bob_kyber.public_key,
        &alice_dilithium.secret_key,
    ).unwrap();

    FileProcessor::save_encrypted_file(&encrypted_file, &encryption_result).unwrap();

    // Get file info
    let metadata = FileProcessor::get_file_info(&encrypted_file).unwrap();
    
    assert_eq!(metadata.filename(), "metadata_test.txt");
    assert_eq!(metadata.original_size(), test_data.len() as u64);
    assert!(metadata.encrypted_size() > metadata.original_size());
    assert!(metadata.timestamp() > 0);
}

#[test]
fn test_algorithm_info() {
    let info = get_algorithm_info();
    
    // Verify algorithm information
    assert_eq!(info.kyber.name, "CRYSTALS-Kyber768");
    assert_eq!(info.kyber.security_level, 192);
    assert_eq!(info.dilithium.name, "CRYSTALS-Dilithium3");
    assert_eq!(info.dilithium.security_level, 192);
    assert_eq!(info.aes.name, "AES-256-GCM");
    
    // Verify key sizes are reasonable
    assert!(info.kyber.public_key_size > 0);
    assert!(info.kyber.secret_key_size > 0);
    assert!(info.dilithium.public_key_size > 0);
    assert!(info.dilithium.secret_key_size > 0);
    assert_eq!(info.aes.key_size, 32);
    assert_eq!(info.aes.nonce_size, 12);
}

#[test]
fn test_crypto_identity_validation() {
    // Generate valid crypto identity
    let (kyber_keys, dilithium_keys) = generate_crypto_identity().unwrap();
    
    // Validate it
    let result = enclypt2::crypto::validate_crypto_identity(&kyber_keys, &dilithium_keys);
    assert!(result.is_ok());
}

#[test]
fn test_empty_file_encryption() {
    // Create temporary directories
    let temp_dir = tempdir().unwrap();
    let key_dir = temp_dir.path().join("keys");
    let data_dir = temp_dir.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();

    // Generate key pairs
    let (alice_kyber, alice_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "alice").unwrap();
    let (bob_kyber, bob_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "bob").unwrap();

    // Create empty file
    let input_file = data_dir.join("empty.txt");
    fs::write(&input_file, b"").unwrap();

    // Encrypt empty file
    let encrypted_file = data_dir.join("empty.enc");
    let encryption_result = FileProcessor::encrypt_file(
        &input_file,
        &bob_kyber.public_key,
        &alice_dilithium.secret_key,
    ).unwrap();

    FileProcessor::save_encrypted_file(&encrypted_file, &encryption_result).unwrap();

    // Decrypt empty file
    let decrypted_file = data_dir.join("empty_decrypted.txt");
    let loaded_result = FileProcessor::load_encrypted_file(&encrypted_file).unwrap();
    
    let decrypted_data = FileProcessor::decrypt_file(
        &loaded_result,
        &bob_kyber.secret_key,
        &alice_dilithium.public_key,
    ).unwrap();

    FileProcessor::write_file(&decrypted_file, &decrypted_data).unwrap();

    // Verify
    let read_data = fs::read(&decrypted_file).unwrap();
    assert_eq!(read_data, b"");
}

#[test]
fn test_binary_file_encryption() {
    // Create temporary directories
    let temp_dir = tempdir().unwrap();
    let key_dir = temp_dir.path().join("keys");
    let data_dir = temp_dir.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();

    // Generate key pairs
    let (alice_kyber, alice_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "alice").unwrap();
    let (bob_kyber, bob_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "bob").unwrap();

    // Create binary test data
    let test_data: Vec<u8> = (0..=255).collect(); // All byte values
    let input_file = data_dir.join("binary_test.bin");
    fs::write(&input_file, &test_data).unwrap();

    // Encrypt binary file
    let encrypted_file = data_dir.join("binary_test.enc");
    let encryption_result = FileProcessor::encrypt_file(
        &input_file,
        &bob_kyber.public_key,
        &alice_dilithium.secret_key,
    ).unwrap();

    FileProcessor::save_encrypted_file(&encrypted_file, &encryption_result).unwrap();

    // Decrypt binary file
    let decrypted_file = data_dir.join("binary_test_decrypted.bin");
    let loaded_result = FileProcessor::load_encrypted_file(&encrypted_file).unwrap();
    
    let decrypted_data = FileProcessor::decrypt_file(
        &loaded_result,
        &bob_kyber.secret_key,
        &alice_dilithium.public_key,
    ).unwrap();

    FileProcessor::write_file(&decrypted_file, &decrypted_data).unwrap();

    // Verify
    let read_data = fs::read(&decrypted_file).unwrap();
    assert_eq!(read_data, test_data);
}
