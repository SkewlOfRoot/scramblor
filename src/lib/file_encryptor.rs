use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::lib::aes_encryptor::EncryptedBytes;

use super::aes_encryptor;

pub fn encrypt_file(file_path: &Path, password: &str) -> Result<String, Box<dyn Error>> {
    let file_content = read_bytes_from_file(file_path);

    let mut byte_data: Vec<u8> = Vec::new();
    byte_data.extend_from_slice(file_path.extension().unwrap().as_encoded_bytes());
    byte_data.extend_from_slice(&file_content);

    let result: EncryptedBytes =
        aes_encryptor::encrypt(byte_data, password).expect("Failed to encrypt file.");

    let mut new_file_path: PathBuf = PathBuf::from(file_path);
    new_file_path.set_extension("scr");

    match File::create(new_file_path.clone()) {
        Ok(mut file) => match file.write_all(&result.bytes) {
            Ok(_) => println!("Enctypted file: {:?}", new_file_path),
            Err(e) => eprintln!("Failed to write encrypted data to file: {}", e),
        },
        Err(e) => eprintln!("Failed to create file: {}", e),
    }

    Ok(String::new())
}

pub fn decrypt_file(file_path: &Path, password: &str) -> Result<String, Box<dyn Error>> {
    let file_content = read_bytes_from_file(file_path);

    let result: Vec<u8> =
        aes_encryptor::decrypt(file_content, password).expect("Failed to decrypt file.");

    let (orig_file_ext, decrypted_data) = result.split_at(3);
    let orig_file_ext = String::from_utf8(orig_file_ext.to_vec()).unwrap();

    let decrypted_file_path: PathBuf = PathBuf::from(file_path);
    //decrypted_file_path.set_extension(orig_file_ext);
    let file_stem = decrypted_file_path.file_stem().unwrap();
    // while !decrypted_file_path.exists() {
    //     decrypted_file_path.se(file_name)
    // }
    println!("File ext: {}", orig_file_ext);

    Ok(String::new())
}

fn read_bytes_from_file(file_path: &Path) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    File::open(file_path)
        .unwrap()
        .read_to_end(&mut buffer)
        .expect("Failed to read bytes from file.");
    buffer
}
