use criterion::{black_box, criterion_group, criterion_main, Criterion};
use enclypt2::{
    crypto::{
        generate_crypto_identity, get_algorithm_info,
        encapsulate, decapsulate, sign, verify,
        encrypt_data, decrypt_data, derive_aes_key,
        generate_aes_key, generate_nonce,
    },
    file_processor::FileProcessor,
};
use tempfile::tempdir;
use std::fs;
use std::time::Instant;

// Test data sizes for comprehensive benchmarking
const TEST_SIZES: [usize; 8] = [64, 256, 1024, 4096, 16384, 65536, 262144, 1048576]; // 64B to 1MB
const ITERATIONS: usize = 1000;

fn benchmark_kyber_comprehensive(c: &mut Criterion) {
    let mut group = c.benchmark_group("Kyber768 Comprehensive");
    
    // Key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let (kyber_keys, _) = generate_crypto_identity().unwrap();
            black_box(kyber_keys);
        });
    });
    
    // Encapsulation
    group.bench_function("encapsulation", |b| {
        let (kyber_keys, _) = generate_crypto_identity().unwrap();
        b.iter(|| {
            let encapsulation = encapsulate(&kyber_keys.public_key).unwrap();
            black_box(encapsulation);
        });
    });
    
    // Decapsulation
    group.bench_function("decapsulation", |b| {
        let (kyber_keys, _) = generate_crypto_identity().unwrap();
        let encapsulation = encapsulate(&kyber_keys.public_key).unwrap();
        b.iter(|| {
            let shared_secret = decapsulate(&kyber_keys.secret_key, &encapsulation.ciphertext).unwrap();
            black_box(shared_secret);
        });
    });
    
    // Key derivation
    group.bench_function("key_derivation", |b| {
        let (kyber_keys, _) = generate_crypto_identity().unwrap();
        let encapsulation = encapsulate(&kyber_keys.public_key).unwrap();
        b.iter(|| {
            let aes_key = derive_aes_key(&encapsulation.shared_secret, b"test-context").unwrap();
            black_box(aes_key);
        });
    });
    
    group.finish();
}

fn benchmark_dilithium_comprehensive(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dilithium3 Comprehensive");
    
    // Key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let (_, dilithium_keys) = generate_crypto_identity().unwrap();
            black_box(dilithium_keys);
        });
    });
    
    // Signing with different message sizes
    for size in TEST_SIZES.iter() {
        let message = vec![42u8; *size];
        group.bench_function(&format!("signing_{}b", size), |b| {
            let (_, dilithium_keys) = generate_crypto_identity().unwrap();
            b.iter(|| {
                let signature = sign(&message, &dilithium_keys.secret_key).unwrap();
                black_box(signature);
            });
        });
    }
    
    // Verification with different message sizes
    for size in TEST_SIZES.iter() {
        let message = vec![42u8; *size];
        group.bench_function(&format!("verification_{}b", size), |b| {
            let (_, dilithium_keys) = generate_crypto_identity().unwrap();
            let signature = sign(&message, &dilithium_keys.secret_key).unwrap();
            b.iter(|| {
                verify(&message, &signature, &dilithium_keys.public_key).unwrap();
            });
        });
    }
    
    // Single message signing (replacing multiple message signing)
    group.bench_function("sign_single_message", |b| {
        let (_, dilithium_keys) = generate_crypto_identity().unwrap();
        let message = b"Test message for signing";
        b.iter(|| {
            let signature = sign(message, &dilithium_keys.secret_key).unwrap();
            black_box(signature);
        });
    });
    
    // Single message verification (replacing multiple message verification)
    group.bench_function("verify_single_message", |b| {
        let (_, dilithium_keys) = generate_crypto_identity().unwrap();
        let message = b"Test message for signing";
        let signature = sign(message, &dilithium_keys.secret_key).unwrap();
        b.iter(|| {
            verify(message, &signature, &dilithium_keys.public_key).unwrap();
        });
    });
    
    group.finish();
}

fn benchmark_aes_comprehensive(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-GCM Comprehensive");
    
    // Key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let key = generate_aes_key().unwrap();
            black_box(key);
        });
    });
    
    // Nonce generation
    group.bench_function("nonce_generation", |b| {
        b.iter(|| {
            let nonce = generate_nonce().unwrap();
            black_box(nonce);
        });
    });
    
    // Encryption with different data sizes
    for size in TEST_SIZES.iter() {
        let data = vec![42u8; *size];
        group.bench_function(&format!("encryption_{}b", size), |b| {
            let key = generate_aes_key().unwrap();
            b.iter(|| {
                let (ciphertext, nonce) = encrypt_data(&data, &key).unwrap();
                black_box((ciphertext, nonce));
            });
        });
    }
    
    // Decryption with different data sizes
    for size in TEST_SIZES.iter() {
        let data = vec![42u8; *size];
        group.bench_function(&format!("decryption_{}b", size), |b| {
            let key = generate_aes_key().unwrap();
            let (ciphertext, nonce) = encrypt_data(&data, &key).unwrap();
            b.iter(|| {
                let plaintext = decrypt_data(&ciphertext, &key, &nonce).unwrap();
                black_box(plaintext);
            });
        });
    }
    
    group.finish();
}

fn benchmark_file_operations_comprehensive(c: &mut Criterion) {
    let mut group = c.benchmark_group("File Operations Comprehensive");
    
    // File encryption with different sizes
    for size in TEST_SIZES.iter() {
        group.bench_function(&format!("encrypt_file_{}b", size), |b| {
            let temp_dir = tempdir().unwrap();
            let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
            let (bob_kyber, _) = generate_crypto_identity().unwrap();
            
            let test_data = vec![42u8; *size];
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
    
    // File decryption with different sizes
    for size in TEST_SIZES.iter() {
        group.bench_function(&format!("decrypt_file_{}b", size), |b| {
            let temp_dir = tempdir().unwrap();
            let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
            let (bob_kyber, _) = generate_crypto_identity().unwrap();
            
            let test_data = vec![42u8; *size];
            let input_file = temp_dir.path().join("test.txt");
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
    }
    
    group.finish();
}

fn benchmark_throughput_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("Throughput Analysis");
    
    // Test throughput at different file sizes
    for size in TEST_SIZES.iter() {
        group.bench_function(&format!("throughput_encrypt_{}b", size), |b| {
            let temp_dir = tempdir().unwrap();
            let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
            let (bob_kyber, _) = generate_crypto_identity().unwrap();
            
            let test_data = vec![42u8; *size];
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
    let mut group = c.benchmark_group("Memory Usage Analysis");
    
    // Key storage memory usage
    group.bench_function("key_storage_memory", |b| {
        b.iter(|| {
            let (kyber_keys, dilithium_keys) = generate_crypto_identity().unwrap();
            let total_size = kyber_keys.public_key.len() + kyber_keys.secret_key.len() +
                           dilithium_keys.public_key.len() + dilithium_keys.secret_key.len();
            black_box(total_size);
        });
    });
    
    // Encryption overhead analysis
    for size in [1024, 10240, 102400, 1048576].iter() {
        group.bench_function(&format!("encryption_overhead_{}b", size), |b| {
            let temp_dir = tempdir().unwrap();
            let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
            let (bob_kyber, _) = generate_crypto_identity().unwrap();
            
            let test_data = vec![42u8; *size];
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
    }
    
    group.finish();
}

fn benchmark_concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Concurrent Operations");
    
    // Concurrent key generation
    group.bench_function("concurrent_key_generation_4", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4).map(|_| {
                std::thread::spawn(|| {
                    generate_crypto_identity().unwrap()
                })
            }).collect();
            
            for handle in handles {
                let (kyber, dilithium) = handle.join().unwrap();
                black_box((kyber, dilithium));
            }
        });
    });
    
    // Concurrent encryption
    group.bench_function("concurrent_encryption_4", |b| {
        b.iter(|| {
            let temp_dir = tempdir().unwrap();
            let (alice_kyber, alice_dilithium) = generate_crypto_identity().unwrap();
            let (bob_kyber, _) = generate_crypto_identity().unwrap();
            
            let test_data = vec![42u8; 1024];
            let input_file = temp_dir.path().join("test.txt");
            fs::write(&input_file, &test_data).unwrap();
            
            let handles: Vec<_> = (0..4).map(|_| {
                let input_file = input_file.clone();
                let bob_kyber = bob_kyber.clone();
                let alice_dilithium = alice_dilithium.clone();
                
                std::thread::spawn(move || {
                    FileProcessor::encrypt_file(
                        &input_file,
                        &bob_kyber.public_key,
                        &alice_dilithium.secret_key,
                    ).unwrap()
                })
            }).collect();
            
            for handle in handles {
                let result = handle.join().unwrap();
                black_box(result);
            }
        });
    });
    
    group.finish();
}

fn benchmark_error_handling(c: &mut Criterion) {
    let mut group = c.benchmark_group("Error Handling Performance");
    
    // Invalid key size error handling
    group.bench_function("invalid_key_size_error", |b| {
        let invalid_key = vec![0u8; 100]; // Wrong size
        b.iter(|| {
            let result = encapsulate(&invalid_key);
            black_box(result);
        });
    });
    
    // Invalid signature error handling
    group.bench_function("invalid_signature_error", |b| {
        let (_, dilithium_keys) = generate_crypto_identity().unwrap();
        let message = b"Test message";
        let invalid_signature = vec![0u8; 100]; // Wrong size
        b.iter(|| {
            let result = verify(message, &invalid_signature, &dilithium_keys.public_key);
            black_box(result);
        });
    });
    
    group.finish();
}

fn generate_detailed_metrics() {
    println!("🔐 Enclypt 2.0 Comprehensive Performance Analysis");
    println!("=================================================");
    println!("{}", get_algorithm_info());
    println!();
    
    // Generate detailed metrics for CSV export
    let mut csv_data = Vec::new();
    
    // Test all operations with multiple iterations
    let operations: Vec<(&str, Box<dyn Fn() -> (std::time::Duration, usize)>)> = vec![
        ("kyber_key_generation", Box::new(|| {
            let start = Instant::now();
            let (kyber_keys, _) = generate_crypto_identity().unwrap();
            let duration = start.elapsed();
            (duration, kyber_keys.public_key.len() + kyber_keys.secret_key.len())
        })),
        ("dilithium_key_generation", Box::new(|| {
            let start = Instant::now();
            let (_, dilithium_keys) = generate_crypto_identity().unwrap();
            let duration = start.elapsed();
            (duration, dilithium_keys.public_key.len() + dilithium_keys.secret_key.len())
        })),
        ("aes_key_generation", Box::new(|| {
            let start = Instant::now();
            let key = generate_aes_key().unwrap();
            let duration = start.elapsed();
            (duration, key.len())
        })),
    ];
    
    for (op_name, operation) in operations.iter() {
        let mut times = Vec::new();
        let mut memory_usage = 0;
        
        for _ in 0..ITERATIONS {
            let (duration, memory) = operation();
            times.push(duration);
            memory_usage = memory;
        }
        
        times.sort();
        let mean_time = times.iter().sum::<std::time::Duration>() / ITERATIONS as u32;
        let median_time = times[ITERATIONS / 2];
        let p95_time = times[(ITERATIONS * 95) / 100];
        let p99_time = times[(ITERATIONS * 99) / 100];
        
        csv_data.push((
            op_name.to_string(),
            mean_time.as_micros() as f64,
            median_time.as_micros() as f64,
            p95_time.as_micros() as f64,
            p99_time.as_micros() as f64,
            memory_usage,
            1_000_000.0 / mean_time.as_micros() as f64, // ops/sec
        ));
        
                 println!("{}: mean={:.2}μs, median={:.2}μs, p95={:.2}μs, p99={:.2}μs, memory={}B, throughput={:.0} ops/sec",
             op_name, mean_time.as_micros(), median_time.as_micros(), 
             p95_time.as_micros(), p99_time.as_micros(), memory_usage,
             1_000_000.0 / mean_time.as_micros() as f64);
    }
    
    // Test encryption/decryption with different data sizes
    for size in TEST_SIZES.iter() {
        let data = vec![42u8; *size];
        
        // AES encryption
        let mut times = Vec::new();
        for _ in 0..ITERATIONS {
            let key = generate_aes_key().unwrap();
            let start = Instant::now();
            let (ciphertext, _) = encrypt_data(&data, &key).unwrap();
            let duration = start.elapsed();
            times.push(duration);
            black_box(ciphertext);
        }
        
        times.sort();
        let mean_time = times.iter().sum::<std::time::Duration>() / ITERATIONS as u32;
        let throughput_mbps = (*size as f64 * 1_000_000.0) / (mean_time.as_micros() as f64 * 1024.0 * 1024.0);
        
        csv_data.push((
            format!("aes_encryption_{}b", size),
            mean_time.as_micros() as f64,
            times[ITERATIONS / 2].as_micros() as f64,
            times[(ITERATIONS * 95) / 100].as_micros() as f64,
            times[(ITERATIONS * 99) / 100].as_micros() as f64,
            *size,
            throughput_mbps,
        ));
        
        println!("aes_encryption_{}b: mean={:.2}μs, throughput={:.2} MB/s", 
            size, mean_time.as_micros(), throughput_mbps);
    }
    
    // Save CSV data
    let csv_content = generate_csv(&csv_data);
    fs::write("comprehensive_benchmark_results.csv", csv_content).unwrap();
    println!("\n📊 Detailed results saved to: comprehensive_benchmark_results.csv");
}

fn generate_csv(data: &[(String, f64, f64, f64, f64, usize, f64)]) -> String {
    let mut csv = String::new();
    csv.push_str("Operation,Mean_Time_μs,Median_Time_μs,P95_Time_μs,P99_Time_μs,Data_Size_Bytes,Throughput\n");
    
    for (operation, mean, median, p95, p99, size, throughput) in data {
        csv.push_str(&format!("{},{:.2},{:.2},{:.2},{:.2},{},{:.2}\n", 
            operation, mean, median, p95, p99, size, throughput));
    }
    
    csv
}

criterion_group! {
    name = comprehensive_benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(2))
        .measurement_time(std::time::Duration::from_secs(5));
    targets = 
        benchmark_kyber_comprehensive,
        benchmark_dilithium_comprehensive,
        benchmark_aes_comprehensive,
        benchmark_file_operations_comprehensive,
        benchmark_throughput_analysis,
        benchmark_memory_usage,
        benchmark_concurrent_operations,
        benchmark_error_handling
}

criterion_main!(comprehensive_benches);

// Print detailed metrics when benchmarks start
#[ctor::ctor]
fn init() {
    generate_detailed_metrics();
}
