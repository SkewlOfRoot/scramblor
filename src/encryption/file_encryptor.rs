use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::aes_encryptor::{self, EncryptedBytes};

const FILE_EXTENSION: &str = "scr";

pub fn encrypt_file(file_path: &Path, password: &str) -> anyhow::Result<EncryptionResult> {
    let file_content = read_bytes_from_file(file_path)?;

    let extension = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if extension.len() > 255 {
        return Err(anyhow::anyhow!("File extension is too long."));
    }

    // First byte will store the length of the original file extension
    // followed by the extension itself and then the file content.
    // E.g.: <extension length><extension><file content>
    let mut byte_data: Vec<u8> = Vec::new();
    let extension_length = u8::try_from(extension.len())?;
    byte_data.push(extension_length);
    byte_data.extend_from_slice(extension.as_bytes());
    byte_data.extend_from_slice(&file_content);

    let result: EncryptedBytes = match aes_encryptor::encrypt(byte_data, password) {
        Ok(it) => it,
        Err(err) => return Err(anyhow::anyhow!("Failed to encrypt file: {}", err)),
    };

    let mut new_file_path: PathBuf = PathBuf::from(file_path);
    new_file_path.set_extension(FILE_EXTENSION);
    let new_file_path = unique_file_name(new_file_path)?;

    let mut file = File::create_new(&new_file_path)?;
    file.write_all(&result.bytes)?;

    Ok(EncryptionResult::new(
        format!("File encrypted successfully: {}", new_file_path.display()).as_str(),
    ))
}

pub fn decrypt_file(file_path: &Path, password: &str) -> anyhow::Result<EncryptionResult> {
    let file_content = read_bytes_from_file(file_path)?;

    let result: Vec<u8> = aes_encryptor::decrypt(file_content, password)?;

    // First byte is the length of the original file extension.
    let (extension_length, rest) = result
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("Invalid encrypted file format: no data found."))?;

    // Get the original file extension and the decrypted data.
    let (orig_file_ext, decrypted_data) = rest.split_at(*extension_length as usize);
    let extension = String::from_utf8(orig_file_ext.to_vec())?;

    let mut decrypted_file_path: PathBuf = PathBuf::from(file_path);
    decrypted_file_path.set_extension(&extension);
    let new_file_name = unique_file_name(decrypted_file_path)?;

    let mut file = File::create_new(&new_file_name)?;
    file.write_all(decrypted_data)?;

    Ok(EncryptionResult::new(
        format!("File decrypted successfully: {}", new_file_name.display()).as_str(),
    ))
}

fn unique_file_name(proposed_file_path: PathBuf) -> anyhow::Result<PathBuf> {
    let file_stem = proposed_file_path.file_stem().ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to get file stem from proposed file path: {}",
            proposed_file_path.display()
        )
    })?;
    let extension = proposed_file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");

    let mut proposed_file_path = proposed_file_path.clone();
    let mut counter: u8 = 0;

    loop {
        let mut new_file_name = file_stem.to_os_string();

        if counter > 0 {
            new_file_name.push(".");
            new_file_name.push(counter.to_string());
        }

        if !extension.is_empty() {
            new_file_name.push(".");
            new_file_name.push(extension);
        }

        proposed_file_path.set_file_name(new_file_name);

        if !proposed_file_path.exists() {
            break;
        }
        counter += 1;
    }

    Ok(proposed_file_path)
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
