use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::aes_encryptor;

pub fn encrypt_file(file_path: &Path, password: &str) -> Result<String, Box<dyn Error>> {
    let mut buffer: Vec<u8> = Vec::new();
    File::open(file_path)
        .unwrap()
        .read_to_end(&mut buffer)
        .expect("Failed to read bytes from file.");

    let result = aes_encryptor::encrypt(buffer, password).expect("Failed to encrypt file.");

    println!("Encrypted file: {:#?}", result);

    Ok(String::new())
}

pub fn decrypt_file(file_path: &Path, password: &str) -> Result<String, Box<dyn Error>> {
    Ok(String::new())
}
