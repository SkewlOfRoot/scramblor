use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::aes_encryptor::{self, EncryptedBytes};

pub fn encrypt_file(file_path: &Path, password: &str) -> Result<(), Box<dyn Error>> {
    let file_content = read_bytes_from_file(file_path);

    let mut byte_data: Vec<u8> = Vec::new();
    byte_data.extend_from_slice(file_path.extension().unwrap().as_encoded_bytes());
    byte_data.extend_from_slice(&file_content);

    let result: EncryptedBytes =
        aes_encryptor::encrypt(byte_data, password).expect("Failed to encrypt file.");

    let mut new_file_path: PathBuf = PathBuf::from(file_path);
    new_file_path.set_extension("scr");

    match File::create_new(new_file_path.clone()) {
        Ok(mut file) => match file.write_all(&result.bytes) {
            Ok(_) => println!("Encrypted file: {:?}", new_file_path),
            Err(e) => eprintln!("Failed to write encrypted data to file: {}", e),
        },
        Err(e) => eprintln!("Failed to create file: {}", e),
    }
    Ok(())
}

pub fn decrypt_file(file_path: &Path, password: &str) -> Result<(), Box<dyn Error>> {
    let file_content = read_bytes_from_file(file_path);

    let result: Vec<u8> =
        aes_encryptor::decrypt(file_content, password).expect("Failed to decrypt file.");

    let (orig_file_ext, decrypted_data) = result.split_at(3);
    let orig_file_ext = String::from_utf8(orig_file_ext.to_vec()).unwrap();

    let decrypted_file_path: PathBuf = PathBuf::from(file_path);
    let new_file_name = unique_file_name(decrypted_file_path, &orig_file_ext);

    match File::create_new(new_file_name.clone()) {
        Ok(mut decrypted_file) => match decrypted_file.write_all(decrypted_data) {
            Ok(_) => println!("Decrypted file: {}", new_file_name),
            Err(e) => eprintln!("Failed to write decrypted data to file: {}", e),
        },
        Err(e) => {
            eprintln!("Failed to create file: {}", e)
        }
    }
    Ok(())
}

fn unique_file_name(decrypted_file_path: PathBuf, orig_file_ext: &String) -> String {
    let file_stem = decrypted_file_path.file_stem().unwrap();
    let mut decrypted_file_path = decrypted_file_path.clone();
    let mut counter: u8 = 0;
    loop {
        let mut new_file_name = file_stem.to_os_string();
        if counter > 0 {
            new_file_name.push(".");
            new_file_name.push(counter.to_string());
        }
        new_file_name.push(".");
        new_file_name.push(orig_file_ext);
        decrypted_file_path.set_file_name(new_file_name);
        if !decrypted_file_path.exists() {
            break;
        }
        counter += 1;
    }
    String::from(decrypted_file_path.to_str().unwrap())
}

fn read_bytes_from_file(file_path: &Path) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    File::open(file_path)
        .unwrap()
        .read_to_end(&mut buffer)
        .expect("Failed to read bytes from file.");
    buffer
}
