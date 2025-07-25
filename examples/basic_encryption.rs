//! Basic file encryption example for Enclypt 2.0

use enclypt2::{
    crypto::{kyber, dilithium},
    file_processor::FileProcessor,
};
use std::fs;
use std::io::Write;
use tempfile::NamedTempFile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Enclypt 2.0 - Basic Encryption Example");
    
    // Generate key pairs
    let dilithium_keys = dilithium::generate_keypair()?;
    let kyber_keys = kyber::generate_keypair()?;
    
    // Create sample file
    let mut sample_file = NamedTempFile::new()?;
    sample_file.write_all(b"Hello, post-quantum world!")?;
    
    // Encrypt
    let result = FileProcessor::encrypt_file(
        sample_file.path(),
        &kyber_keys.public_key,
        &dilithium_keys.secret_key,
    )?;
    
    // Decrypt
    let decrypted = FileProcessor::decrypt_file(
        &result,
        &kyber_keys.secret_key,
        &dilithium_keys.public_key,
    )?;
    
    println!("✅ Encryption/Decryption successful!");
    println!("Original: Hello, post-quantum world!");
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
    
    Ok(())
}
