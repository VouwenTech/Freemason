use polodb_core::bson::doc;
use polodb_core::Database;
use serde::{Deserialize, Serialize};

use crate::crypto::secretbox_chacha20_poly1305::{Key, Nonce};
use crate::db::constants::SECRET_COLLECTION;
use crate::db::security::SecurityAtRest;
use crate::db::DbError;

/// Full data for handling a secret key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub file_name: String,
    pub total_chunks: usize,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
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
        let db = match Database::open_file(self.url.clone()) {
            Ok(db) => db,
            Err(_) => {
                return Err(DbError {
                    message: "Failed to open database".to_string(),
                });
            }
        };
        let sec_collection = db.collection(SECRET_COLLECTION);

        match sec_collection.insert_one(secret_entry) {
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
    pub async fn get_secret(&self, id: &str) -> Result<SecretEntry, DbError> {
        let db = match Database::open_file(self.url.clone()) {
            Ok(db) => db,
            Err(_) => {
                return Err(DbError {
                    message: "Failed to open database".to_string(),
                });
            }
        };
        let sec_collection = db.collection(SECRET_COLLECTION);

        let filter = doc! { "file_name": id };
        let secret_entry: SecretEntry = match sec_collection.find_one(filter) {
            Ok(Some(entry)) => entry,
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

        Ok(secret_entry)
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
}
