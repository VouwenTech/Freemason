use std::num::NonZeroU32;
use crate::crypto::sign_ed25519::{PublicKey, SecretKey};
use crate::crypto::secretbox_chacha20_poly1305::{Key, Nonce, seal,open};

const CREDENTIAL_LEN: usize = ring::digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];
static PBKDF2_ALG: ring::pbkdf2::Algorithm = ring::pbkdf2::PBKDF2_HMAC_SHA256;

/// Generates a salt for the PBKDF2 algorithm
/// 
/// ### Arguments
/// 
/// * `id` - ID of the salt entry
/// * `salt_component` - Base salt component
fn generate_salt(id: &str, salt_component: [u8; 16]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(salt_component.len() +
                                      id.as_bytes().len());
    salt.extend(salt_component.as_ref());
    salt.extend(id.as_bytes());
    salt
}

/// Derives a key from a passphrase using PBKDF2
/// 
/// ### Arguments
/// 
/// * `id` - ID of the salt entry
/// * `passphrase` - Passphrase to derive the key from
/// * `salt_component` - Base salt component
/// * `pbkdf2_iterations` - Number of PBKDF2 iterations
pub fn derive_rest_key(id: &str, passphrase: &str, salt_component: [u8; 16], pbkdf2_iterations: NonZeroU32) -> [u8; CREDENTIAL_LEN] {
    let mut rest_key: [u8; CREDENTIAL_LEN] = [0u8; CREDENTIAL_LEN];
    let salt = generate_salt(id, salt_component);
    ring::pbkdf2::derive(PBKDF2_ALG, pbkdf2_iterations, &salt, passphrase.as_bytes(), &mut rest_key);

    rest_key
}

/// Encrypts a keypair for storage
/// 
/// ### Arguments
/// 
/// * `rest_key` - Rest key
/// * `nonce` - Nonce
/// * `keypair` - Key pair to encrypt
pub fn encrypt_keys_for_storage(rest_key: [u8; CREDENTIAL_LEN], nonce: &Nonce, keypair: (PublicKey, SecretKey)) -> (Vec<u8>, Vec<u8>) {
    let pub_key = seal(keypair.0.as_ref().to_vec(), nonce, &Key::from_slice(&rest_key).unwrap());
    let secret_key = seal(keypair.1.as_ref().to_vec(), nonce, &Key::from_slice(&rest_key).unwrap());

    (pub_key.unwrap(), secret_key.unwrap())
}

/// Decrypts a keypair from storage
/// 
/// ### Arguments
/// 
/// * `rest_key` - Rest key
/// * `nonce` - Nonce
/// * `keypair` - Key pair to decrypt
pub fn decrypt_keys_from_storage(rest_key: [u8; CREDENTIAL_LEN], nonce: &Nonce, keypair: (Vec<u8>, Vec<u8>)) -> (PublicKey, SecretKey) {
    let pub_key = open(keypair.0, nonce, &Key::from_slice(&rest_key).unwrap());
    let secret_key = open(keypair.1, nonce, &Key::from_slice(&rest_key).unwrap());

    (PublicKey::from_slice(&pub_key.unwrap()).unwrap(), SecretKey::from_slice(&secret_key.unwrap()).unwrap())
}