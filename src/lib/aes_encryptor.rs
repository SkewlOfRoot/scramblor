use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;

pub fn encrypt(bytes: Vec<u8>, password: &str) -> Result<EncryptedBytes, aes_gcm::Error> {
    // The encryption key can be generated randomly:
    let key = Aes256Gcm::generate_key(OsRng);

    // Transformed from a byte array:
    //let key: &[u8; 32] = &[42; 32];
    //let key: &Key<Aes256Gcm> = key.into();

    // Note that you can get byte array from slice using the `TryInto` trait:
    //let key: &[u8] = &[42; 32];
    let key: Vec<u8> = password.as_bytes().try_into().unwrap();

    // Alternatively, the key can be transformed directly from a byte slice
    // (panicks on length mismatch):
    let key = Key::<Aes256Gcm>::from_slice(&key);

    let cipher = Aes256Gcm::new(key);

    // let mut nonce_key = [0u8; 16];
    // OsRng.fill_bytes(&mut nonce_key);
    // let random_u64 = OsRng.next_u64();

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    //let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, bytes.as_ref())?;

    Ok(EncryptedBytes::new(ciphertext, nonce_bytes))
}

pub fn decrypt(password: &str) -> Result<(), aes_gcm::Error> {
    println!("Decrypting...");
    Ok(())
}

#[derive(Debug)]
pub struct EncryptedBytes {
    bytes: Vec<u8>,
    nonce: [u8; 12],
}

impl EncryptedBytes {
    fn new(bytes: Vec<u8>, nonce: [u8; 12]) -> Self {
        Self { bytes, nonce }
    }
}
