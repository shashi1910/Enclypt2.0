//! # Enclypt 2.0 - Post-Quantum Secure File Transfer System
//! 
//! Post-quantum secure file transfer system using NIST-standardized algorithms.

#![deny(missing_docs)]
#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

pub mod crypto;
pub mod file_processor;
pub mod key_manager;
pub mod cli;

#[cfg(feature = "server")]
pub mod api;

// Re-export commonly used types
pub use crypto::{CryptoError, CryptoResult, EncryptionResult, FileMetadata, KeyPair};
pub use file_processor::FileProcessor;
pub use key_manager::{KeyManager, KeyInfo};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
