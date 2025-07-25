use anyhow::Result;
use clap::Parser;
use enclypt2::{
    cli::{Cli, Commands},
    crypto::{dilithium, kyber},
    file_processor::FileProcessor,
    key_manager::KeyManager,
};
use std::fs;
use tracing::{info, error};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output, name, .. } => {
            info!("Generating key pair for: {}", name);
            
            let kyber_keypair = kyber::generate_keypair()?;
            let dilithium_keypair = dilithium::generate_keypair()?;
            
            KeyManager::save_keypairs(&output, &name, &kyber_keypair, &dilithium_keypair)?;
            
            println!("✅ Key pair generated successfully!");
            println!("📁 Keys saved to: {}/", output.display());
        }

        Commands::Encrypt { input, recipient_key, sender_key, output, .. } => {
            info!("Encrypting file: {:?}", input);
            
            let recipient_kyber_public = KeyManager::load_key(&recipient_key)?;
            let sender_dilithium_secret = KeyManager::load_key(&sender_key)?;
            
            let encryption_result = FileProcessor::encrypt_file(
                &input,
                &recipient_kyber_public,
                &sender_dilithium_secret,
            )?;
            
            FileProcessor::save_encrypted_file(&output, &encryption_result)?;
            
            println!("✅ File encrypted successfully!");
            println!("📁 Encrypted file saved to: {}", output.display());
        }

        Commands::Decrypt { input, recipient_key, sender_key, output, .. } => {
            info!("Decrypting file: {:?}", input);
            
            let recipient_kyber_secret = KeyManager::load_key(&recipient_key)?;
            let sender_dilithium_public = KeyManager::load_key(&sender_key)?;
            
            let encryption_result = FileProcessor::load_encrypted_file(&input)?;
            let decrypted_data = FileProcessor::decrypt_file(
                &encryption_result,
                &recipient_kyber_secret,
                &sender_dilithium_public,
            )?;
            
            fs::write(&output, decrypted_data)?;
            
            println!("✅ File decrypted successfully!");
            println!("📁 Decrypted file saved to: {}", output.display());
        }

        _ => {
            println!("Command not implemented yet");
        }
    }

    Ok(())
}
