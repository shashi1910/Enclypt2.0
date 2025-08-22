//! REST API server for Enclypt 2.0
//! 
//! This module provides a HTTP REST API for secure file upload and download
//! operations using post-quantum cryptography.

#[cfg(feature = "server")]
pub mod handlers;
#[cfg(feature = "server")]
pub mod middleware;
#[cfg(feature = "server")]
pub mod types;

#[cfg(feature = "server")]
pub use handlers::*;
#[cfg(feature = "server")]
pub use types::*;

#[cfg(feature = "server")]
use axum::{
    http::{StatusCode, Method},
    response::Json,
    routing::{get, post},
    Router,
};
#[cfg(feature = "server")]
use serde_json::{json, Value};
#[cfg(feature = "server")]
use std::collections::HashMap;
#[cfg(feature = "server")]
use tower_http::cors::{CorsLayer, Any};

/// Create the main application router with all endpoints
#[cfg(feature = "server")]
pub fn create_app() -> Router {
    // Create CORS layer
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(Any)
        .allow_origin(Any);

    Router::new()
        // Health check endpoint
        .route("/api/v1/health", get(health_check))
        
        // File operations
        .route("/api/v1/files/upload", post(upload_file))
        .route("/api/v1/files/:file_id/download", post(download_file))
        .route("/api/v1/files/:file_id/info", get(get_file_info))
        .route("/api/v1/files/:file_id/verify", post(verify_file))
        
        // Key management
        .route("/api/v1/keys/generate", post(generate_keys))
        .route("/api/v1/keys/:key_id", get(get_key_info_api))
        
        // System information
        .route("/api/v1/info", get(system_info))
        
        // Add CORS middleware
        .layer(cors)
        
        // Add other middleware
        .layer(axum::middleware::from_fn(middleware::request_logging))
}

/// Health check endpoint
#[cfg(feature = "server")]
async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "version": crate::VERSION,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "algorithms": {
            "kyber": "CRYSTALS-Kyber768",
            "dilithium": "CRYSTALS-Dilithium3",
            "aes": "AES-256-GCM"
        }
    }))
}

/// Get system information
#[cfg(feature = "server")]
async fn system_info() -> Json<Value> {
    Json(json!({
        "name": "Enclypt 2.0",
        "version": crate::VERSION,
        "description": "Post-quantum secure file transfer system",
        "algorithms": {
            "kyber": {
                "name": "CRYSTALS-Kyber768",
                "security_level": 192,
                "key_sizes": {
                    "public": crate::crypto::kyber::KYBER_PUBLICKEYBYTES,
                    "secret": crate::crypto::kyber::KYBER_SECRETKEYBYTES,
                    "ciphertext": crate::crypto::kyber::KYBER_CIPHERTEXTBYTES
                }
            },
            "dilithium": {
                "name": "CRYSTALS-Dilithium3",
                "security_level": 192,
                "key_sizes": {
                    "public": crate::crypto::dilithium::DILITHIUM3_PUBLICKEYBYTES,
                    "secret": crate::crypto::dilithium::DILITHIUM3_SECRETKEYBYTES,
                    "max_signature": crate::crypto::dilithium::DILITHIUM3_SIGNBYTES
                }
            },
            "aes": {
                "name": "AES-256-GCM",
                "security_level": 256,
                "key_size": crate::crypto::aes_gcm::AES_GCM_KEY_SIZE,
                "nonce_size": crate::crypto::aes_gcm::AES_GCM_NONCE_SIZE
            }
        },
        "features": [
            "post-quantum-cryptography",
            "end-to-end-encryption",
            "digital-signatures",
            "file-transfer",
            "rest-api"
        ],
        "capabilities": {
            "max_file_size": "10GB",
            "supported_formats": ["any"],
            "authentication": "digital-signatures"
        }
    }))
}

#[cfg(not(feature = "server"))]
/// Placeholder function when server feature is not enabled
pub fn create_app() -> &'static str {
    "Server feature not enabled. Please compile with --features server"
}

#[cfg(feature = "server")]
#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;
    
    #[tokio::test]
    async fn test_health_check() {
        let app = create_app();
        let server = TestServer::new(app).expect("Should create test server");
        
        let response = server.get("/api/v1/health").await;
        
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let body: Value = response.json();
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["version"], crate::VERSION);
    }
    
    #[tokio::test]
    async fn test_system_info() {
        let app = create_app();
        let server = TestServer::new(app).expect("Should create test server");
        
        let response = server.get("/api/v1/info").await;
        
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let body: Value = response.json();
        assert_eq!(body["name"], "Enclypt 2.0");
        assert_eq!(body["algorithms"]["kyber"]["name"], "CRYSTALS-Kyber768");
    }
}