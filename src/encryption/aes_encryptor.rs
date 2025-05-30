use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    aes::Aes256,
    Aes256Gcm, AesGcm, Key, Nonce,
};
use rand::RngCore;
use sha2::digest::{
    consts::{B0, B1},
    typenum::{UInt, UTerm},
};

pub fn encrypt(bytes: Vec<u8>, password: &str) -> anyhow::Result<EncryptedBytes> {
    let cipher = generate_cipher(password);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.inner.encrypt(nonce, bytes.as_ref()).map_err(|e| {
        anyhow::anyhow!("Failed to encrypt data with the provided password: {:?}", e)
    })?;

    Ok(EncryptedBytes::new(ciphertext, nonce_bytes))
}

fn generate_cipher(password: &str) -> Cipher {
    let key: Vec<u8> = password.as_bytes().into();
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(key);
    Cipher { inner: cipher }
}

pub fn decrypt(encrypted_bytes: Vec<u8>, password: &str) -> anyhow::Result<Vec<u8>> {
    let (nonce_bytes, ciphertext) = encrypted_bytes.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = generate_cipher(password);

    match cipher.inner.decrypt(nonce, ciphertext) {
        Ok(decrypted_plaintext) => Ok(decrypted_plaintext),
        Err(e) => Err(anyhow::anyhow!("Failed to decrypt data: {:?}", e)),
    }
}

#[derive(Debug)]
pub struct EncryptedBytes {
    pub bytes: Vec<u8>,
}

impl EncryptedBytes {
    fn new(bytes: Vec<u8>, nonce: [u8; 12]) -> Self {
        let mut encrypted_data: Vec<u8> = Vec::new();
        encrypted_data.extend(nonce);
        encrypted_data.extend(bytes);

        Self {
            bytes: encrypted_data,
        }
    }
}

#[allow(clippy::type_complexity)]
struct Cipher {
    inner: AesGcm<Aes256, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
}
