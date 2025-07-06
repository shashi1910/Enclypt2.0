Enclypt 2.0: Post-Quantum Secure File Transfer System

🚀 What is Enclypt 2.0?

Enclypt 2.0 is a post-quantum secure file transfer system designed to protect sensitive files against current and future threats posed by quantum computers.

Today, most secure file transfer systems rely on RSA and Elliptic Curve Cryptography (ECC). With the development of quantum computers capable of running Shor’s algorithm, these methods will become insecure, creating a “harvest now, decrypt later” risk where encrypted data can be collected today and decrypted in the future.

Enclypt 2.0 addresses this by using quantum-resistant cryptographic algorithms for secure file transfer and storage, ensuring that sensitive data remains confidential even in a post-quantum world.

⸻

🔄 How is Enclypt 2.0 different from Enclypt (Previous Version)?

Enclypt, was:

✅ A Flask-based web application using Fernet (AES-128) symmetric encryption for encrypting and decrypting files.
✅ Provided a user-friendly web interface for uploading files, generating encryption keys, and securely downloading encrypted or decrypted files.
✅ Served as a practical learning project for implementing secure file handling workflows.

However, Enclypt had limitations:

❌ It used classical cryptographic methods (Fernet, AES-128), which will become insecure in a post-quantum world.
❌ No secure key exchange mechanism resistant to quantum attacks.
❌ Limited to small-scale, single-user file handling without scalability considerations.
❌ No benchmarking or modular architecture for future upgrades.

⸻

Enclypt 2.0 builds upon these learnings to provide:

✅ Post-Quantum Security: Uses CRYSTALS-Kyber for key encapsulation and CRYSTALS-Dilithium for digital signatures, ensuring future-proof encryption.
✅ AES-256-GCM for high-speed, secure symmetric encryption.
✅ A command-line interface and optional REST API for practical workflows while maintaining strong cryptographic guarantees.
✅ A modular, scalable design to serve as the foundation for future quantum-safe file transfer platforms.

⸻

🛠 What will this project do?

Enclypt 2.0 will:

✅ Allow users to encrypt and decrypt files securely using post-quantum cryptography.
✅ Use Kyber for quantum-safe key exchange during file transfer.
✅ Use AES-256-GCM for efficient encryption of file contents.
✅ Use Dilithium for digital signatures to verify file authenticity and integrity.
✅ Provide a clean CLI interface for secure uploads, downloads, encryption, and decryption.
✅ Optionally include a REST API server for testing secure uploads/downloads.

⸻

🔒 Why is this project needed?
	•	Quantum Threat Readiness: Quantum computers will break traditional encryption; using post-quantum cryptography future-proofs confidentiality.
	•	Long-Term Data Security: Files encrypted today may need to stay secure for years; quantum-safe methods prevent future compromise.
	•	Practical Security: Translates advanced cryptographic research into a usable system for real-world secure file transfer needs.
	•	Evolution from Enclypt: This project is a natural progression from your previous Enclypt system, aligning it with modern cryptographic standards and enterprise readiness.

⸻

⚙️ Project Status

Currently in early development with the goal of:

✅ Demonstrating file encryption and decryption using Kyber + AES-256-GCM.
✅ Demonstrating signature generation and verification using Dilithium.
✅ Providing a working CLI for local file encryption/decryption tests.
✅ Exploring optional REST API integration for file upload/download workflows.

⸻

📚 Tech Stack
	•	Rust: For performance, safety, and low-level cryptographic control.
	•	liboqs: For CRYSTALS-Kyber and Dilithium post-quantum cryptography.
	•	RustCrypto: For AES-256-GCM encryption.
	•	REST API (Optional): Using Axum or Actix for secure upload/download testing.

⸻

📦 Future Plans

Once the minimal implementation is stable, Enclypt 2.0 will expand to include:

✅ A GUI for easy secure file uploads/downloads.
✅ Cloud storage integration (S3, MinIO) for scalable deployment.
✅ Mobile and desktop clients for seamless secure file handling.
✅ Advanced key management, crypto-agility for future algorithm upgrades, and policy enforcement for enterprise workflows.

⸻

🤝 Contributions

Currently under active solo development. Contributions, discussions, and testing feedback are welcome as the project progresses.

⸻

📝 License

MIT License

⸻

✨ Summary

Enclypt 2.0 continues the mission of Enclypt—secure file handling for everyone—while upgrading it for the post-quantum era to ensure that what you encrypt today remains protected tomorrow.
