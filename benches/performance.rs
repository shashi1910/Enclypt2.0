use criterion::{black_box, criterion_group, criterion_main, Criterion};
use enclypt2::{
    crypto::{generate_crypto_identity, get_algorithm_info},
    file_processor::FileProcessor,
};
use tempfile::tempdir;
use std::fs;

fn benchmark_kyber_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber Operations");
    
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let (kyber_keys, _) = generate_crypto_identity().unwrap();
            black_box(kyber_keys);
        });
    });
    
    group.bench_function("encapsulation", |b| {
        let (kyber_keys, _) = generate_crypto_identity().unwrap();
        b.iter(|| {
            let encapsulation = enclypt2::crypto::encapsulate(&kyber_keys.public_key).unwrap();
            black_box(encapsulation);
        });
    });
    
    group.bench_function("decapsulation", |b| {
        let (kyber_keys, _) = generate_crypto_identity().unwrap();
        let encapsulation = enclypt2::crypto::encapsulate(&kyber_keys.public_key).unwrap();
        b.iter(|| {
            let shared_secret = enclypt2::crypto::decapsulate(&kyber_keys.secret_key, &encapsulation.ciphertext).unwrap();
            black_box(shared_secret);
        });
    });
    
    group.finish();
}

fn benchmark_dilithium_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium Operations");
    
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let (_, dilithium_keys) = generate_crypto_identity().unwrap();
            black_box(dilithium_keys);
        });
    });
    
    group.bench_function("signing", |b| {
        let (_, dilithium_keys) = generate_crypto_identity().unwrap();
        let message = b"Test message for signing";
        b.iter(|| {
            let signature = enclypt2::crypto::sign(message, &dilithium_keys.secret_key).unwrap();
            black_box(signature);
        });
    });
    
    group.bench_function("verification", |b| {
        let (_, dilithium_keys) = generate_crypto_identity().unwrap();
        let message = b"Test message for signing";
        let signature = enclypt2::crypto::sign(message, &dilithium_keys.secret_key).unwrap();
        b.iter(|| {
            enclypt2::crypto::verify(message, &signature, &dilithium_keys.public_key).unwrap();
        });
    });
    
    group.finish();
}

fn benchmark_aes_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES Operations");
    
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let key = enclypt2::crypto::generate_aes_key().unwrap();
            black_box(key);
        });
    });
    
    group.bench_function("encryption_1kb", |b| {
        let key = enclypt2::crypto::generate_aes_key().unwrap();
        let data = vec![42u8; 1024];
        b.iter(|| {
            let (ciphertext, nonce) = enclypt2::crypto::encrypt_data(&data, &key).unwrap();
            black_box((ciphertext, nonce));
        });
    });
    
    group.bench_function("decryption_1kb", |b| {
        let key = enclypt2::crypto::generate_aes_key().unwrap();
        let data = vec![42u8; 1024];
        let (ciphertext, nonce) = enclypt2::crypto::encrypt_data(&data, &key).unwrap();
        b.iter(|| {
            let plaintext = enclypt2::crypto::decrypt_data(&ciphertext, &key, &nonce).unwrap();
            black_box(plaintext);
        });
    });
    
    group.bench_function("encryption_1mb", |b| {
        let key = enclypt2::crypto::generate_aes_key().unwrap();
        let data = vec![42u8; 1024 * 1024];
        b.iter(|| {
            let (ciphertext, nonce) = enclypt2::crypto::encrypt_data(&data, &key).unwrap();
            black_box((ciphertext, nonce));
        });
    });
    
    group.bench_function("decryption_1mb", |b| {
        let key = enclypt2::crypto::generate_aes_key().unwrap();
        let data = vec![42u8; 1024 * 1024];
        let (ciphertext, nonce) = enclypt2::crypto::encrypt_data(&data, &key).unwrap();
        b.iter(|| {
            let plaintext = enclypt2::crypto::decrypt_data(&ciphertext, &key, &nonce).unwrap();
            black_box(plaintext);
        });
    });
    
    group.finish();
}

fn benchmark_file_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("File Operations");
    
    group.bench_function("encrypt_1kb", |b| {
        let temp_dir = tempdir().unwrap();
        let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
        let (bob_kyber, _) = generate_crypto_identity().unwrap();
        
        let test_data = vec![42u8; 1024];
        let input_file = temp_dir.path().join("test_1kb.txt");
        fs::write(&input_file, &test_data).unwrap();
        
        b.iter(|| {
            let result = FileProcessor::encrypt_file(
                &input_file,
                &bob_kyber.public_key,
                &alice_dilithium.secret_key,
            ).unwrap();
            black_box(result);
        });
    });
    
    group.bench_function("encrypt_1mb", |b| {
        let temp_dir = tempdir().unwrap();
        let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
        let (bob_kyber, _) = generate_crypto_identity().unwrap();
        
        let test_data = vec![42u8; 1024 * 1024];
        let input_file = temp_dir.path().join("test_1mb.txt");
        fs::write(&input_file, &test_data).unwrap();
        
        b.iter(|| {
            let result = FileProcessor::encrypt_file(
                &input_file,
                &bob_kyber.public_key,
                &alice_dilithium.secret_key,
            ).unwrap();
            black_box(result);
        });
    });
    
    group.bench_function("decrypt_1kb", |b| {
        let temp_dir = tempdir().unwrap();
        let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
        let (bob_kyber, _) = generate_crypto_identity().unwrap();
        
        let test_data = vec![42u8; 1024];
        let input_file = temp_dir.path().join("test_1kb.txt");
        fs::write(&input_file, &test_data).unwrap();
        
        let encryption_result = FileProcessor::encrypt_file(
            &input_file,
            &bob_kyber.public_key,
            &alice_dilithium.secret_key,
        ).unwrap();
        
        b.iter(|| {
            let decrypted = FileProcessor::decrypt_file(
                &encryption_result,
                &bob_kyber.secret_key,
                &alice_dilithium.public_key,
            ).unwrap();
            black_box(decrypted);
        });
    });
    
    group.bench_function("decrypt_1mb", |b| {
        let temp_dir = tempdir().unwrap();
        let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
        let (bob_kyber, _) = generate_crypto_identity().unwrap();
        
        let test_data = vec![42u8; 1024 * 1024];
        let input_file = temp_dir.path().join("test_1mb.txt");
        fs::write(&input_file, &test_data).unwrap();
        
        let encryption_result = FileProcessor::encrypt_file(
            &input_file,
            &bob_kyber.public_key,
            &alice_dilithium.secret_key,
        ).unwrap();
        
        b.iter(|| {
            let decrypted = FileProcessor::decrypt_file(
                &encryption_result,
                &bob_kyber.secret_key,
                &alice_dilithium.public_key,
            ).unwrap();
            black_box(decrypted);
        });
    });
    
    group.finish();
}

fn benchmark_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("Throughput");
    
    // Test different file sizes
    let sizes = [1024, 10240, 102400, 1048576]; // 1KB, 10KB, 100KB, 1MB
    
    for size in sizes {
        group.bench_function(&format!("encrypt_{}b", size), |b| {
            let temp_dir = tempdir().unwrap();
            let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
            let (bob_kyber, _) = generate_crypto_identity().unwrap();
            
            let test_data = vec![42u8; size];
            let input_file = temp_dir.path().join("test.txt");
            fs::write(&input_file, &test_data).unwrap();
            
            b.iter(|| {
                let result = FileProcessor::encrypt_file(
                    &input_file,
                    &bob_kyber.public_key,
                    &alice_dilithium.secret_key,
                ).unwrap();
                black_box(result);
            });
        });
    }
    
    group.finish();
}

fn benchmark_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory Usage");
    
    group.bench_function("key_generation_memory", |b| {
        b.iter(|| {
            let (kyber_keys, dilithium_keys) = generate_crypto_identity().unwrap();
            let total_size = kyber_keys.public_key.len() + kyber_keys.secret_key.len() +
                           dilithium_keys.public_key.len() + dilithium_keys.secret_key.len();
            black_box(total_size);
        });
    });
    
    group.bench_function("encryption_overhead", |b| {
        let temp_dir = tempdir().unwrap();
        let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
        let (bob_kyber, _) = generate_crypto_identity().unwrap();
        
        let test_data = vec![42u8; 1024 * 1024]; // 1MB
        let input_file = temp_dir.path().join("test.txt");
        fs::write(&input_file, &test_data).unwrap();
        
        b.iter(|| {
            let result = FileProcessor::encrypt_file(
                &input_file,
                &bob_kyber.public_key,
                &alice_dilithium.secret_key,
            ).unwrap();
            let overhead = result.total_size() - result.metadata.original_size() as usize;
            black_box(overhead);
        });
    });
    
    group.finish();
}

fn print_algorithm_info() {
    println!("🔐 Enclypt 2.0 Performance Benchmark");
    println!("=====================================");
    println!("{}", get_algorithm_info());
    println!();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(2));
    targets = 
        benchmark_kyber_operations,
        benchmark_dilithium_operations,
        benchmark_aes_operations,
        benchmark_file_operations,
        benchmark_throughput,
        benchmark_memory_usage
}

criterion_main!(benches);

// Print algorithm information when benchmarks start
#[ctor::ctor]
fn init() {
    print_algorithm_info();
}