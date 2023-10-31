use super::constants::{PBKDF2_ITERATIONS, SALT_BASE};
use crate::crypto::secretbox_chacha20_poly1305::{open, seal, Key, Nonce};
use crate::crypto::sign_ed25519::{PublicKey, SecretKey};
use crate::crypto::utils::generate_nonce;
use std::num::NonZeroU32;

const CREDENTIAL_LEN: usize = ring::digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];
static PBKDF2_ALG: ring::pbkdf2::Algorithm = ring::pbkdf2::PBKDF2_HMAC_SHA256;

/// Details and attributes for handling security at rest
#[derive(Debug, Clone)]
pub struct SecurityAtRest {
    pub nonce: Nonce,
    pub pbkdf2_iterations: NonZeroU32,
    pub salt_component: [u8; 16],
}

impl SecurityAtRest {
    /// Creates a new security at rest instance, with all sensible, secure defaults
    pub fn new() -> Self {
        let nonce = Nonce::from_slice(&generate_nonce()).unwrap();

        SecurityAtRest {
            nonce,
            pbkdf2_iterations: PBKDF2_ITERATIONS.unwrap(),
            salt_component: SALT_BASE,
        }
    }

    /// Generates a salt for the PBKDF2 algorithm
    ///
    /// ### Arguments
    ///
    /// * `id` - ID of the salt entry
    /// * `salt_component` - Base salt component
    fn generate_salt(&self, id: &str) -> Vec<u8> {
        let mut salt = Vec::with_capacity(self.salt_component.len() + id.as_bytes().len());
        salt.extend(self.salt_component.as_ref());
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
    pub fn derive_rest_key(&self, id: &str, passphrase: &str) -> [u8; CREDENTIAL_LEN] {
        let mut rest_key: [u8; CREDENTIAL_LEN] = [0u8; CREDENTIAL_LEN];
        let salt = self.generate_salt(id);
        ring::pbkdf2::derive(
            PBKDF2_ALG,
            self.pbkdf2_iterations,
            &salt,
            passphrase.as_bytes(),
            &mut rest_key,
        );

        rest_key
    }

    /// Encrypts a key and nonce for storage
    ///
    /// ### Arguments
    ///
    /// * `rest_key` - Rest key
    /// * `key` - Key to encrypt
    /// * `nonce` - Nonce to encrypt
    pub fn encrypt_key_and_nonce_for_storage(
        &self,
        rest_key: [u8; CREDENTIAL_LEN],
        key: Key,
        nonce: Nonce,
    ) -> (Vec<u8>, Vec<u8>) {
        let encrypted_key = seal(
            key.as_ref().to_vec(),
            &self.nonce,
            &Key::from_slice(&rest_key).unwrap(),
        );
        let encrypted_nonce = seal(
            nonce.as_ref().to_vec(),
            &self.nonce,
            &Key::from_slice(&rest_key).unwrap(),
        );

        (encrypted_key.unwrap(), encrypted_nonce.unwrap())
    }

    /// Decrypts a key and nonce from storage
    ///
    /// ### Arguments
    ///
    /// * `rest_key` - Rest key
    /// * `key` - Key to decrypt
    /// * `nonce` - Nonce to decrypt
    pub fn decrypt_key_and_nonce_for_storage(
        &self,
        rest_key: [u8; CREDENTIAL_LEN],
        key: Vec<u8>,
        nonce: Vec<u8>,
    ) -> (Key, Nonce) {
        let decrypted_key = open(key, &self.nonce, &Key::from_slice(&rest_key).unwrap());
        let decrypted_nonce = open(nonce, &self.nonce, &Key::from_slice(&rest_key).unwrap());

        (
            Key::from_slice(&decrypted_key.unwrap()).unwrap(),
            Nonce::from_slice(&decrypted_nonce.unwrap()).unwrap(),
        )
    }

    /// Encrypts a keypair for storage
    ///
    /// ### Arguments
    ///
    /// * `rest_key` - Rest key
    /// * `nonce` - Nonce
    /// * `keypair` - Key pair to encrypt
    pub fn encrypt_keys_for_storage(
        &self,
        rest_key: [u8; CREDENTIAL_LEN],
        keypair: (PublicKey, SecretKey),
    ) -> (Vec<u8>, Vec<u8>) {
        let pub_key = seal(
            keypair.0.as_ref().to_vec(),
            &self.nonce,
            &Key::from_slice(&rest_key).unwrap(),
        );
        let secret_key = seal(
            keypair.1.as_ref().to_vec(),
            &self.nonce,
            &Key::from_slice(&rest_key).unwrap(),
        );

        (pub_key.unwrap(), secret_key.unwrap())
    }

    /// Decrypts a keypair from storage
    ///
    /// ### Arguments
    ///
    /// * `rest_key` - Rest key
    /// * `nonce` - Nonce
    /// * `keypair` - Key pair to decrypt
    pub fn decrypt_keys_from_storage(
        &self,
        rest_key: [u8; CREDENTIAL_LEN],
        keypair: (Vec<u8>, Vec<u8>),
    ) -> (PublicKey, SecretKey) {
        let pub_key = open(keypair.0, &self.nonce, &Key::from_slice(&rest_key).unwrap());
        let secret_key = open(keypair.1, &self.nonce, &Key::from_slice(&rest_key).unwrap());

        (
            PublicKey::from_slice(&pub_key.unwrap()).unwrap(),
            SecretKey::from_slice(&secret_key.unwrap()).unwrap(),
        )
    }
}
