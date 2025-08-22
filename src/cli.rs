use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, error};

use crate::crypto::get_algorithm_info;
use crate::file_processor::FileProcessor;
use crate::key_manager::KeyManager;

/// Enclypt 2.0 - Post-Quantum Secure File Transfer System
#[derive(Parser)]
#[command(name = "enclypt2")]
#[command(about = "Post-quantum secure file encryption and transfer")]
#[command(version = "2.0.0")]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate new cryptographic key pairs
    Keygen {
        /// Name for the key pair (e.g., "alice", "bob")
        #[arg(short, long)]
        name: String,
        
        /// Output directory for key files
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        
        /// Force overwrite existing keys
        #[arg(short, long)]
        force: bool,
    },
    
    /// Encrypt a file for a recipient
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,
        
        /// Recipient's public key file
        #[arg(short, long)]
        recipient_key: PathBuf,
        
        /// Sender's secret key file
        #[arg(short, long)]
        sender_key: PathBuf,
        
        /// Output file for encrypted data
        #[arg(short, long)]
        output: PathBuf,
        
        /// Overwrite output file if it exists
        #[arg(short, long)]
        force: bool,
    },
    
    /// Decrypt a file
    Decrypt {
        /// Input encrypted file
        #[arg(short, long)]
        input: PathBuf,
        
        /// Recipient's secret key file
        #[arg(short, long)]
        recipient_key: PathBuf,
        
        /// Sender's public key file
        #[arg(short, long)]
        sender_key: PathBuf,
        
        /// Output file for decrypted data
        #[arg(short, long)]
        output: PathBuf,
        
        /// Overwrite output file if it exists
        #[arg(short, long)]
        force: bool,
    },
    
    /// Show information about an encrypted file
    Info {
        /// Encrypted file to examine
        #[arg(short, long)]
        input: PathBuf,
    },
    
    /// Verify the integrity of an encrypted file
    Verify {
        /// Encrypted file to verify
        #[arg(short, long)]
        input: PathBuf,
        
        /// Recipient's secret key file
        #[arg(short, long)]
        recipient_key: PathBuf,
        
        /// Sender's public key file
        #[arg(short, long)]
        sender_key: PathBuf,
    },
    
    /// List available key pairs
    ListKeys {
        /// Key directory to list
        #[arg(short, long)]
        directory: Option<PathBuf>,
    },
    
    /// Delete key pairs
    DeleteKeys {
        /// Name of the key pair to delete
        #[arg(short, long)]
        name: String,
        
        /// Key directory
        #[arg(short, long)]
        directory: Option<PathBuf>,
        
        /// Confirm deletion without prompting
        #[arg(short, long)]
        yes: bool,
    },
    
    /// Show cryptographic algorithm information
    Algorithms,
    
    /// Start a web server for file transfer (optional feature)
    #[cfg(feature = "server")]
    Serve {
        /// Host address to bind to
        #[arg(short, long, default_value = "127.0.0.1")]
        host: String,
        
        /// Port to bind to
        #[arg(short, long, default_value = "8080")]
        port: u16,
        
        /// Key directory for server keys
        #[arg(short, long)]
        key_dir: Option<PathBuf>,
    },
}

/// Handle the keygen command
pub fn handle_keygen(name: &str, output: &PathBuf, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    info!("Generating key pairs for '{}'", name);
    
    // Check if keys already exist
    if !force {
        let key_dir = if output.is_dir() {
            output.clone()
        } else {
            output.parent().unwrap_or(output).to_path_buf()
        };
        
        if KeyManager::validate_keypair_files(&key_dir, name)? {
            error!("Key pairs for '{}' already exist. Use --force to overwrite.", name);
            return Err("Key pairs already exist".into());
        }
    }
    
    // Generate and save key pairs
    let (kyber_keys, dilithium_keys) = KeyManager::generate_and_save_keypairs(output, name)?;
    
    println!("✅ Key pairs generated successfully for '{}'", name);
    println!("📁 Location: {}", output.display());
    println!("🔑 Kyber public key: {} bytes", kyber_keys.public_key.len());
    println!("🔑 Kyber secret key: {} bytes", kyber_keys.secret_key.len());
    println!("🔐 Dilithium public key: {} bytes", dilithium_keys.public_key.len());
    println!("🔐 Dilithium secret key: {} bytes", dilithium_keys.secret_key.len());
    
    Ok(())
}

/// Handle the encrypt command
pub fn handle_encrypt(
    input: &PathBuf,
    recipient_key: &PathBuf,
    sender_key: &PathBuf,
    output: &PathBuf,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Encrypting file: {}", input.display());
    
    // Check if output file exists
    if output.exists() && !force {
        error!("Output file '{}' already exists. Use --force to overwrite.", output.display());
        return Err("Output file already exists".into());
    }
    
    // Load keys
    let recipient_public_key = KeyManager::load_key(recipient_key)?;
    let sender_secret_key = KeyManager::load_key(sender_key)?;
    
    // Encrypt the file
    let encryption_result = FileProcessor::encrypt_file(input, &recipient_public_key, &sender_secret_key)?;
    
    // Save encrypted file
    FileProcessor::save_encrypted_file(output, &encryption_result)?;
    
    println!("✅ File encrypted successfully");
    println!("📁 Input: {} ({} bytes)", input.display(), encryption_result.metadata.original_size());
    println!("📁 Output: {} ({} bytes)", output.display(), encryption_result.total_size());
    println!("🔐 Signed by: {}", encryption_result.metadata.filename());
    
    Ok(())
}

/// Handle the decrypt command
pub fn handle_decrypt(
    input: &PathBuf,
    recipient_key: &PathBuf,
    sender_key: &PathBuf,
    output: &PathBuf,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Decrypting file: {}", input.display());
    
    // Check if output file exists
    if output.exists() && !force {
        error!("Output file '{}' already exists. Use --force to overwrite.", output.display());
        return Err("Output file already exists".into());
    }
    
    // Load keys
    let recipient_secret_key = KeyManager::load_key(recipient_key)?;
    let sender_public_key = KeyManager::load_key(sender_key)?;
    
    // Load encrypted file
    let encryption_result = FileProcessor::load_encrypted_file(input)?;
    
    // Decrypt the file
    let decrypted_data = FileProcessor::decrypt_file(&encryption_result, &recipient_secret_key, &sender_public_key)?;
    
    // Save decrypted file
    FileProcessor::write_file(output, &decrypted_data)?;
    
    println!("✅ File decrypted successfully");
    println!("📁 Input: {} ({} bytes)", input.display(), encryption_result.total_size());
    println!("📁 Output: {} ({} bytes)", output.display(), decrypted_data.len());
    println!("🔐 Original filename: {}", encryption_result.metadata.filename());
    
    Ok(())
}

/// Handle the info command
pub fn handle_info(input: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    info!("Getting file info: {}", input.display());
    
    let metadata = FileProcessor::get_file_info(input)?;
    
    println!("📄 File Information:");
    println!("   Original filename: {}", metadata.filename());
    println!("   Original size: {} bytes", metadata.original_size());
    println!("   Encrypted size: {} bytes", metadata.encrypted_size());
    println!("   Timestamp: {}", metadata.timestamp());
    println!("   Content hash: {}", hex::encode(&metadata.content_hash()[..8]));
    
    Ok(())
}

/// Handle the verify command
pub fn handle_verify(
    input: &PathBuf,
    recipient_key: &PathBuf,
    sender_key: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Verifying file: {}", input.display());
    
    // Load keys
    let recipient_secret_key = KeyManager::load_key(recipient_key)?;
    let sender_public_key = KeyManager::load_key(sender_key)?;
    
    // Verify file integrity
    let is_valid = FileProcessor::verify_file_integrity(input, &recipient_secret_key, &sender_public_key)?;
    
    if is_valid {
        println!("✅ File integrity verification successful");
        println!("🔐 Digital signature is valid");
        println!("🔒 File has not been tampered with");
    } else {
        println!("❌ File integrity verification failed");
        println!("⚠️  File may have been corrupted or tampered with");
        return Err("File integrity check failed".into());
    }
    
    Ok(())
}

/// Handle the list-keys command
pub fn handle_list_keys(directory: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let key_dir = directory.unwrap_or_else(|| {
        KeyManager::get_default_key_dir().unwrap_or_else(|_| PathBuf::from("."))
    });
    
    info!("Listing keys in: {}", key_dir.display());
    
    let key_names = KeyManager::list_keypairs(&key_dir)?;
    
    if key_names.is_empty() {
        println!("📁 No key pairs found in {}", key_dir.display());
    } else {
        println!("📁 Available key pairs in {}:", key_dir.display());
        for name in key_names {
            println!("   🔑 {}", name);
        }
    }
    
    Ok(())
}

/// Handle the delete-keys command
pub fn handle_delete_keys(
    name: &str,
    directory: Option<PathBuf>,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_dir = directory.unwrap_or_else(|| {
        KeyManager::get_default_key_dir().unwrap_or_else(|_| PathBuf::from("."))
    });
    
    info!("Deleting keys for '{}' from {}", name, key_dir.display());
    
    // Check if keys exist
    if !KeyManager::validate_keypair_files(&key_dir, name)? {
        error!("No key pairs found for '{}'", name);
        return Err("Key pairs not found".into());
    }
    
    // Confirm deletion
    if !yes {
        println!("⚠️  Are you sure you want to delete all keys for '{}'? (y/N): ", name);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        if !input.trim().to_lowercase().starts_with('y') {
            println!("❌ Key deletion cancelled");
            return Ok(());
        }
    }
    
    // Delete keys
    KeyManager::delete_keypairs(&key_dir, name)?;
    
    println!("✅ Key pairs for '{}' deleted successfully", name);
    
    Ok(())
}

/// Handle the algorithms command
pub fn handle_algorithms() -> Result<(), Box<dyn std::error::Error>> {
    let info = get_algorithm_info();
    println!("{}", info);
    Ok(())
}

#[cfg(feature = "server")]
/// Handle the serve command
pub fn handle_serve(host: &str, port: u16, key_dir: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting web server on {}:{}", host, port);
    
    // This would start the web server
    // For now, just print a message
    println!("🌐 Web server would start on {}:{}", host, port);
    println!("⚠️  Server feature not yet implemented");
    
    Ok(())
}

/// Main CLI handler
pub fn handle_cli(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Keygen { name, output, force } => {
            handle_keygen(&name, &output, force)
        }
        Commands::Encrypt { input, recipient_key, sender_key, output, force } => {
            handle_encrypt(&input, &recipient_key, &sender_key, &output, force)
        }
        Commands::Decrypt { input, recipient_key, sender_key, output, force } => {
            handle_decrypt(&input, &recipient_key, &sender_key, &output, force)
        }
        Commands::Info { input } => {
            handle_info(&input)
        }
        Commands::Verify { input, recipient_key, sender_key } => {
            handle_verify(&input, &recipient_key, &sender_key)
        }
        Commands::ListKeys { directory } => {
            handle_list_keys(directory)
        }
        Commands::DeleteKeys { name, directory, yes } => {
            handle_delete_keys(&name, directory, yes)
        }
        Commands::Algorithms => {
            handle_algorithms()
        }
        #[cfg(feature = "server")]
        Commands::Serve { host, port, key_dir } => {
            handle_serve(&host, port, key_dir)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_cli_parsing() {
        // Test keygen command
        let args = vec!["enclypt2", "keygen", "--name", "test", "--output", "/tmp"];
        let cli = Cli::try_parse_from(args).unwrap();
        
        match cli.command {
            Commands::Keygen { name, output, force } => {
                assert_eq!(name, "test");
                assert_eq!(output, PathBuf::from("/tmp"));
                assert!(!force);
            }
            _ => panic!("Expected Keygen command"),
        }
    }

    #[test]
    fn test_handle_algorithms() {
        // This should not panic
        handle_algorithms().unwrap();
    }
}