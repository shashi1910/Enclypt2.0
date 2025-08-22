//! Basic file encryption example for Enclypt 2.0

use enclypt2::{
    crypto::get_algorithm_info,
    file_processor::FileProcessor,
    key_manager::KeyManager,
};
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Enclypt 2.0 - Post-Quantum Secure File Transfer System");
    println!("=====================================================\n");

    // Show algorithm information
    println!("📊 Cryptographic Algorithms:");
    println!("{}", get_algorithm_info());
    println!();

    // Create a temporary directory for our example
    let temp_dir = tempdir()?;
    let key_dir = temp_dir.path().join("keys");
    let data_dir = temp_dir.path().join("data");

    println!("📁 Working directory: {}", temp_dir.path().display());

    // Step 1: Generate key pairs for Alice and Bob
    println!("\n🔑 Step 1: Generating key pairs...");
    
    let (alice_kyber, alice_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "alice")?;
    let (bob_kyber, bob_dilithium) = KeyManager::generate_and_save_keypairs(&key_dir, "bob")?;
    
    println!("✅ Generated key pairs for Alice and Bob");
    println!("   Alice - Kyber: {}B public, {}B secret", 
        alice_kyber.public_key.len(), alice_kyber.secret_key.len());
    println!("   Alice - Dilithium: {}B public, {}B secret", 
        alice_dilithium.public_key.len(), alice_dilithium.secret_key.len());
    println!("   Bob - Kyber: {}B public, {}B secret", 
        bob_kyber.public_key.len(), bob_kyber.secret_key.len());
    println!("   Bob - Dilithium: {}B public, {}B secret", 
        bob_dilithium.public_key.len(), bob_dilithium.secret_key.len());

    // Step 2: Create a test file
    println!("\n📄 Step 2: Creating test file...");
    
    let test_data = b"Hello, post-quantum world! This is a secret message from Alice to Bob.";
    let input_file = data_dir.join("secret_message.txt");
    std::fs::create_dir_all(&data_dir)?;
    std::fs::write(&input_file, test_data)?;
    
    println!("✅ Created test file: {}", input_file.display());
    println!("   Size: {} bytes", test_data.len());

    // Step 3: Alice encrypts a file for Bob
    println!("\n🔒 Step 3: Alice encrypts file for Bob...");
    
    let encrypted_file = data_dir.join("secret_message.enc");
    let encryption_result = FileProcessor::encrypt_file(
        &input_file,
        &bob_kyber.public_key,      // Bob's public key for encryption
        &alice_dilithium.secret_key, // Alice's secret key for signing
    )?;
    
    FileProcessor::save_encrypted_file(&encrypted_file, &encryption_result)?;
    
    println!("✅ File encrypted successfully");
    println!("   Input: {} bytes", encryption_result.metadata.original_size());
    println!("   Output: {} bytes", encryption_result.total_size());
    println!("   Overhead: {:.1}%", 
        ((encryption_result.total_size() as f64 / encryption_result.metadata.original_size() as f64) - 1.0) * 100.0);

    // Step 4: Show file information
    println!("\n📋 Step 4: File information...");
    
    let metadata = FileProcessor::get_file_info(&encrypted_file)?;
    println!("   Original filename: {}", metadata.filename());
    println!("   Original size: {} bytes", metadata.original_size());
    println!("   Encrypted size: {} bytes", metadata.encrypted_size());
    println!("   Timestamp: {}", metadata.timestamp());
    println!("   Content hash: {}", hex::encode(&metadata.content_hash()[..8]));

    // Step 5: Bob decrypts the file
    println!("\n🔓 Step 5: Bob decrypts the file...");
    
    let decrypted_file = data_dir.join("decrypted_message.txt");
    let loaded_result = FileProcessor::load_encrypted_file(&encrypted_file)?;
    
    let decrypted_data = FileProcessor::decrypt_file(
        &loaded_result,
        &bob_kyber.secret_key,        // Bob's secret key for decryption
        &alice_dilithium.public_key,  // Alice's public key for verification
    )?;
    
    FileProcessor::write_file(&decrypted_file, &decrypted_data)?;
    
    println!("✅ File decrypted successfully");
    println!("   Decrypted size: {} bytes", decrypted_data.len());

    // Step 6: Verify the decrypted content
    println!("\n✅ Step 6: Verifying decrypted content...");
    
    let read_data = std::fs::read(&decrypted_file)?;
    if read_data == test_data {
        println!("✅ Content verification successful!");
        println!("   Original: {}", String::from_utf8_lossy(test_data));
        println!("   Decrypted: {}", String::from_utf8_lossy(&read_data));
    } else {
        println!("❌ Content verification failed!");
        return Err("Decrypted content does not match original".into());
    }

    // Step 7: Verify file integrity
    println!("\n🔍 Step 7: Verifying file integrity...");
    
    let is_valid = FileProcessor::verify_file_integrity(
        &encrypted_file,
        &bob_kyber.secret_key,
        &alice_dilithium.public_key,
    )?;
    
    if is_valid {
        println!("✅ File integrity verification successful");
        println!("   Digital signature is valid");
        println!("   File has not been tampered with");
    } else {
        println!("❌ File integrity verification failed");
        return Err("File integrity check failed".into());
    }

    // Step 8: List available keys
    println!("\n📁 Step 8: Available key pairs...");
    
    let key_names = KeyManager::list_keypairs(&key_dir)?;
    println!("   Found {} key pairs:", key_names.len());
    for name in key_names {
        println!("   - {}", name);
    }

    println!("\n🎉 Example completed successfully!");
    println!("📁 Files created:");
    println!("   - Keys: {}", key_dir.display());
    println!("   - Data: {}", data_dir.display());
    println!("   - Original: {}", input_file.display());
    println!("   - Encrypted: {}", encrypted_file.display());
    println!("   - Decrypted: {}", decrypted_file.display());

    Ok(())
}
