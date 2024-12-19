use serde::{Deserialize, Serialize};

use crate::crypto::secretbox_chacha20_poly1305::{Key, Nonce};
use crate::db::security::SecurityAtRest;
use crate::db::DbError;
use crate::services::ServiceStatus;


/// Full data for handling a secret key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub file_name: String,
    pub total_chunks: usize,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Secret key entry with key and nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntryWithKeyAndNonce {
    pub file_name: String,
    pub total_chunks: usize,
    pub key: Key,
    pub nonce: Nonce,
}

/// Secret key database
#[derive(Debug, Clone)]
pub struct SecretDb {
    url: String,
    security: SecurityAtRest,
}

impl SecretDb {
    /// Creates a new secret database
    ///
    /// ### Arguments
    ///
    /// * `url` - Database URL
    pub fn new(url: String) -> SecretDb {
        SecretDb {
            url,
            security: SecurityAtRest::new(),
        }
    }

    /// Inserts a secret entry into the database
    ///
    /// ### Arguments
    ///
    /// * `secret_entry` - Secret entry to insert
    pub async fn insert_secret(&self, secret_entry: SecretEntry) -> Result<(), DbError> {
        let db = match sled::open(self.url.clone()) {
            Ok(db) => db,
            Err(_) => {
                return Err(DbError {
                    message: "Failed to open database".to_string(),
                });
            }
        };

        // Serialise secret_entry
        let sec_json = serde_json::json!(secret_entry);
        let sec_entry = serde_json::to_vec(&sec_json).unwrap();

        match db.insert(secret_entry.file_name, sec_entry) {
            Ok(_) => Ok(()),
            Err(_) => Err(DbError {
                message: "Failed to insert secret data".to_string(),
            }),
        }
    }

    /// Gets a secret entry from the database
    ///
    /// ### Arguments
    ///
    /// * `id` - ID of the secret entry
    pub async fn get_secret(
        &self,
        id: &str,
        passphrase: &str,
    ) -> Result<SecretEntryWithKeyAndNonce, DbError> {
        let db = match sled::open(self.url.clone()) {
            Ok(db) => db,
            Err(_) => {
                return Err(DbError {
                    message: "Failed to open database".to_string(),
                });
            }
        };

        let secret_entry: SecretEntry = match db.get(id) {
            Ok(Some(entry)) => serde_json::from_slice(&entry).unwrap(),
            Ok(None) => {
                return Err(DbError {
                    message: "Failed to find secret data".to_string(),
                });
            }
            Err(_) => {
                return Err(DbError {
                    message: "Failed to find secret data".to_string(),
                });
            }
        };

        let rest_key = self.security.derive_rest_key(id, passphrase);
        let (key, nonce) = self.security.decrypt_key_and_nonce_for_storage(
            rest_key,
            secret_entry.key,
            secret_entry.nonce,
        );

        Ok(SecretEntryWithKeyAndNonce {
            file_name: secret_entry.file_name,
            total_chunks: secret_entry.total_chunks,
            key,
            nonce,
        })
    }

    /// Creates a secret entry
    ///
    /// ### Arguments
    ///
    /// * `id` - ID of the secret entry
    /// * `passphrase` - Passphrase to derive the key from
    /// * `total_chunks` - Total number of chunks
    /// * `key_and_nonce` - Key and nonce to encrypt
    pub fn create_secret_entry(
        &self,
        id: &str,
        passphrase: &str,
        total_chunks: usize,
        key_and_nonce: (Key, Nonce),
    ) -> SecretEntry {
        let rest_key = self.security.derive_rest_key(id, passphrase);
        let (encrypted_key, encrypted_nonce) = self.security.encrypt_key_and_nonce_for_storage(
            rest_key,
            key_and_nonce.0,
            key_and_nonce.1,
        );

        SecretEntry {
            file_name: id.to_string(),
            total_chunks,
            key: encrypted_key,
            nonce: encrypted_nonce,
        }
    }
  
    /// Checks the service status tied to the secret database
    ///
    /// ### Returns
    ///
    /// * `ServiceStatus` -  Status of the service tied to this secret database
    pub fn check_service_status(&self) -> Result<ServiceStatus, DbError> {
        // ...method implementation...
    }

    /// Collates sensitive service status if necessary and safe
    ///
    /// ### Returns
    ///
    /// * `ServiceStatus` -  Collated service status
    pub fn collate_service_status(&self) -> Result<ServiceStatus, DbError> {
        // ...method implementation...
    }
}