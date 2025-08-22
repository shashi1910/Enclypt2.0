use anyhow::Result;
use clap::Parser;
use enclypt2::cli::{Cli, handle_cli};
use tracing::{info, error};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing with environment-based configuration
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    
    fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    info!("Starting Enclypt 2.0 - Post-Quantum Secure File Transfer System");

    // Parse command line arguments
    let cli = Cli::parse();

    // Handle the command
    match handle_cli(cli) {
        Ok(()) => {
            info!("Command completed successfully");
            Ok(())
        }
        Err(e) => {
            error!("Command failed: {}", e);
            eprintln!("❌ Error: {}", e);
            std::process::exit(1);
        }
    }
}