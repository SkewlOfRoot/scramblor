use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::aes_encryptor::{self, EncryptedBytes};

const FILE_EXTENSION: &str = "scr";

pub fn encrypt_file(file_path: &Path, password: &str) -> anyhow::Result<EncryptionResult> {
    let file_content = read_bytes_from_file(file_path)?;

    let extension = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if extension.len() > 255 {
        return Err(anyhow::anyhow!("File extension is too long."));
    }

    let mut byte_data: Vec<u8> = Vec::new();
    byte_data.extend_from_slice(extension.as_bytes());
    byte_data.extend_from_slice(&file_content);

    let result: EncryptedBytes = match aes_encryptor::encrypt(byte_data, password) {
        Ok(it) => it,
        Err(err) => return Err(anyhow::anyhow!("Failed to encrypt file: {}", err)),
    };

    let mut new_file_path: PathBuf = PathBuf::from(file_path);
    new_file_path.set_extension(FILE_EXTENSION);

    let mut file = File::create_new(&new_file_path)?;
    file.write_all(&result.bytes)?;

    Ok(EncryptionResult::new(
        format!("File encrypted successfully: {}", new_file_path.display()).as_str(),
    ))
}

pub fn decrypt_file(file_path: &Path, password: &str) -> anyhow::Result<EncryptionResult> {
    let file_content = read_bytes_from_file(file_path)?;

    let result: Vec<u8> = aes_encryptor::decrypt(file_content, password)?;

    let (orig_file_ext, decrypted_data) = result.split_at(3);
    let orig_file_ext = String::from_utf8(orig_file_ext.to_vec()).unwrap();

    let decrypted_file_path: PathBuf = PathBuf::from(file_path);
    let new_file_name = unique_file_name(decrypted_file_path, &orig_file_ext);

    let mut file = File::create_new(&new_file_name)?;
    file.write_all(decrypted_data)?;

    Ok(EncryptionResult::new(
        format!("File decrypted successfully: {}", new_file_name).as_str(),
    ))
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

fn read_bytes_from_file(file_path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut buffer: Vec<u8> = Vec::new();
    File::open(file_path)?.read_to_end(&mut buffer)?;
    Ok(buffer)
}

pub struct EncryptionResult {
    pub message: String,
}

impl EncryptionResult {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}
