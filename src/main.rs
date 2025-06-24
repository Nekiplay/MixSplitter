use aes::Aes256;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{KeyIvInit, generic_array::GenericArray};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

#[derive(Serialize, Deserialize)]
struct ChunkInfo {
    hash: String,
    chunk_number: usize,
    size: usize,
}

#[derive(Serialize, Deserialize)]
struct FileMetadata {
    original_name: String,
    extension: Option<String>,
    total_chunks: usize,
    password_hash: String,
    salt: [u8; 16],
    chunks: Vec<ChunkInfo>,
}

struct FileSplitter {
    chunk_size: Option<usize>,
    chunk_count: Option<usize>,
    password: Option<String>,
}

impl FileSplitter {
    fn new(
        chunk_size: Option<usize>,
        chunk_count: Option<usize>,
        password: Option<String>,
    ) -> Self {
        Self {
            chunk_size,
            chunk_count,
            password,
        }
    }

    fn calculate_chunk_size(&self, file_size: usize) -> usize {
        match (self.chunk_size, self.chunk_count) {
            (Some(size), _) => size,
            (None, Some(count)) => (file_size + count - 1) / count,
            (None, None) => 1024 * 1024,
        }
    }

    fn derive_key(&self, salt: &[u8]) -> GenericArray<u8, typenum::U32> {
        let password = self.password.as_ref().unwrap().as_bytes();
        let mut key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(password, salt, 100_000, &mut key);
        GenericArray::from(key)
    }

    fn encrypt_data(&self, data: &[u8], salt: &[u8]) -> Vec<u8> {
        let key = self.derive_key(salt);
        let iv = GenericArray::from([0u8; 16]);
        let cipher = Aes256CbcEnc::new(&key, &iv);

        let mut buffer = vec![0; data.len() + 16];
        let pos = data.len();
        buffer[..pos].copy_from_slice(data);
        let ct = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, pos)
            .unwrap();
        ct.to_vec()
    }

    fn decrypt_data(&self, data: &[u8], salt: &[u8]) -> Vec<u8> {
        let key = self.derive_key(salt);
        let iv = GenericArray::from([0u8; 16]);
        let cipher = Aes256CbcDec::new(&key, &iv);

        let mut buffer = data.to_vec();
        cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .unwrap()
            .to_vec()
    }

    fn split(&self, input_path: &str) -> std::io::Result<()> {
        let path = Path::new(input_path);
        let original_name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("file")
            .to_string();

        let extension = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string());

        let mut input_file = File::open(input_path)?;
        let file_size = input_file.metadata()?.len() as usize;

        let chunk_size = self.calculate_chunk_size(file_size);
        let total_chunks = (file_size + chunk_size - 1) / chunk_size;

        let mut buffer = vec![0; chunk_size];
        let mut chunk_num = 0;
        let mut chunks_info = Vec::new();

        // Generate random salt
        let mut salt = [0u8; 16];
        rand::thread_rng().fill(&mut salt);

        // Create directory for chunks
        let dir_name = format!("{}.chunks", original_name);
        fs::create_dir_all(&dir_name)?;

        loop {
            let bytes_read = input_file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            // Process data (encrypt if password provided)
            let processed_data = if self.password.is_some() {
                self.encrypt_data(&buffer[..bytes_read], &salt)
            } else {
                buffer[..bytes_read].to_vec()
            };

            // Calculate hash
            let mut hasher = Sha256::new();
            hasher.update(&processed_data);
            let hash = hasher.finalize();
            let hash_hex = hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();

            let chunk_path = format!("{}/{}.part", dir_name, hash_hex);
            let mut output_file = File::create(&chunk_path)?;
            output_file.write_all(&processed_data)?;

            chunks_info.push(ChunkInfo {
                hash: hash_hex,
                chunk_number: chunk_num,
                size: processed_data.len(),
            });

            chunk_num += 1;
            println!(
                "Created chunk {}/{}: {}",
                chunk_num, total_chunks, chunk_path
            );
        }

        // Calculate password hash
        let password_hash = if let Some(pass) = &self.password {
            let mut hasher = Sha256::new();
            hasher.update(pass.as_bytes());
            format!("{:x}", hasher.finalize())
        } else {
            String::new()
        };

        // Save metadata
        let metadata = FileMetadata {
            original_name,
            extension,
            total_chunks: chunk_num,
            password_hash,
            salt,
            chunks: chunks_info,
        };

        let metadata_path = format!("{}/metadata.json", dir_name);
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        fs::write(metadata_path, metadata_json)?;

        println!("File split into {} parts", chunk_num);
        Ok(())
    }

    fn join(&self, metadata_path: &str) -> std::io::Result<()> {
        let metadata_json = fs::read_to_string(metadata_path)?;
        let metadata: FileMetadata = serde_json::from_str(&metadata_json)?;

        // Verify password if needed
        if !metadata.password_hash.is_empty() {
            if self.password.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Password is required for this file",
                ));
            }

            let mut hasher = Sha256::new();
            hasher.update(self.password.as_ref().unwrap().as_bytes());
            let provided_hash = format!("{:x}", hasher.finalize());

            if provided_hash != metadata.password_hash {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Incorrect password",
                ));
            }
        }

        let output_name = match &metadata.extension {
            Some(ext) => format!("{}.{}", metadata.original_name, ext),
            None => metadata.original_name.clone(),
        };

        let mut output_file = File::create(&output_name)?;
        let mut hashes_match = true;
        let chunks_dir = Path::new(metadata_path)
            .parent()
            .unwrap_or_else(|| Path::new("."));

        for chunk_info in metadata.chunks {
            let chunk_path = chunks_dir.join(format!("{}.part", chunk_info.hash));
            let mut input_file = File::open(&chunk_path)?;
            let mut buffer = vec![0; chunk_info.size];
            input_file.read_exact(&mut buffer)?;

            // Verify hash
            let mut hasher = Sha256::new();
            hasher.update(&buffer);
            let calculated_hash = hasher.finalize();
            let calculated_hash_hex = calculated_hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();

            if calculated_hash_hex != chunk_info.hash {
                eprintln!(
                    "Hash mismatch in chunk {}! Expected: {}, Got: {}",
                    chunk_info.chunk_number, chunk_info.hash, calculated_hash_hex
                );
                hashes_match = false;
            }

            // Process data (decrypt if password provided)
            let processed_data = if !metadata.password_hash.is_empty() {
                self.decrypt_data(&buffer, &metadata.salt)
            } else {
                buffer
            };

            output_file.write_all(&processed_data)?;
        }

        if hashes_match {
            println!(
                "Successfully joined {} chunks to {}",
                metadata.total_chunks, output_name
            );
        } else {
            eprintln!("File joined but some chunks failed hash verification!");
        }

        Ok(())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage:");
        println!(
            "  To split: {} split <input_file> [--chunk-size SIZE | --chunk-count COUNT] [--password PASS]",
            args[0]
        );
        println!(
            "  To join: {} join <metadata_file> [--password PASS]",
            args[0]
        );
        println!("\nOptions:");
        println!("  --chunk-size SIZE   Set chunk size in bytes");
        println!("  --chunk-count COUNT Set number of chunks");
        println!("  --password PASS     Set password for encryption");
        println!("Note: Use either --chunk-size or --chunk-count, not both");
        return;
    }

    let command = &args[1];
    let mut chunk_size = None;
    let mut chunk_count = None;
    let mut password = None;
    let mut pos_args = Vec::new();

    // Parse optional arguments
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--chunk-size" => {
                if i + 1 < args.len() {
                    chunk_size = Some(args[i + 1].parse().unwrap());
                    i += 2;
                } else {
                    eprintln!("Error: --chunk-size requires a value");
                    return;
                }
            }
            "--chunk-count" => {
                if i + 1 < args.len() {
                    chunk_count = Some(args[i + 1].parse().unwrap());
                    i += 2;
                } else {
                    eprintln!("Error: --chunk-count requires a value");
                    return;
                }
            }
            "--password" => {
                if i + 1 < args.len() {
                    password = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --password requires a value");
                    return;
                }
            }
            _ => {
                pos_args.push(args[i].clone());
                i += 1;
            }
        }
    }

    // Validate that not both chunk options are specified
    if chunk_size.is_some() && chunk_count.is_some() {
        eprintln!("Error: Use either --chunk-size or --chunk-count, not both");
        return;
    }

    let splitter = FileSplitter::new(chunk_size, chunk_count, password);

    match command.as_str() {
        "split" => {
            if pos_args.is_empty() {
                eprintln!("Error: Need input file");
                return;
            }
            if let Err(e) = splitter.split(&pos_args[0]) {
                eprintln!("Error splitting file: {}", e);
            }
        }
        "join" => {
            if pos_args.is_empty() {
                eprintln!("Error: Need metadata file");
                return;
            }
            if let Err(e) = splitter.join(&pos_args[0]) {
                eprintln!("Error joining files: {}", e);
            }
        }
        _ => {
            eprintln!("Unknown command: {}", command);
        }
    }
}
