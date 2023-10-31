use super::security::SecurityAtRest;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{gen_keypair, PublicKey, Signature};
use crate::db::constants::{SIG_COLLECTION, SIG_ID_COLLECTION, SIG_TTL};
use crate::db::DbError;
use polodb_core::bson::doc;
use polodb_core::{Collection, Database};
use serde::{Deserialize, Serialize};

/// Full data for handling a signing, pub/priv keypair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
    pub pk_hash: String,
    pub pub_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub ttl: u32,
    pub timestamp: String,
}

/// ID struct for a signature entry
#[derive(Serialize, Deserialize)]
pub struct SigId {
    pub id: String,
    pub pk_hash: String,
}

/// Signature database
#[derive(Debug, Clone)]
pub struct SignatureDb {
    url: String,
    security: SecurityAtRest,
}

impl SignatureDb {
    /// Creates a new signature database
    ///
    /// ### Arguments
    ///
    /// * `url` - Database URL
    pub fn new(url: String) -> SignatureDb {
        SignatureDb {
            url,
            security: SecurityAtRest::new(),
        }
    }

    /// Gets the signature and signature ID collections
    pub async fn get_collections(
        &self,
    ) -> Result<(Collection<SignatureEntry>, Collection<SigId>), DbError> {
        let db = match Database::open_file(self.url.clone()) {
            Ok(db) => db,
            Err(_) => {
                return Err(DbError {
                    message: "Failed to open database".to_string(),
                });
            }
        };
        let sig_collection = db.collection(SIG_COLLECTION);
        let sig_id_collection = db.collection(SIG_ID_COLLECTION);

        Ok((sig_collection, sig_id_collection))
    }

    /// Inserts signature data into the database
    ///
    /// ### Arguments
    ///
    /// * `message_id` - Message ID
    /// * `signature_data` - Signature data to insert
    pub async fn insert_signature_data(
        &self,
        message_id: String,
        signature_data: SignatureEntry,
    ) -> Result<(), DbError> {
        let colls = self.get_collections().await;

        if let Ok((sig_collection, sig_id_collection)) = colls {
            match sig_id_collection.insert_one(SigId {
                id: message_id,
                pk_hash: signature_data.pk_hash.clone(),
            }) {
                Ok(_) => (),
                Err(_) => {
                    return Err(DbError {
                        message: "Failed to insert signature id".to_string(),
                    });
                }
            }

            return match sig_collection.insert_one(signature_data) {
                Ok(_) => Ok(()),
                Err(_) => Err(DbError {
                    message: "Failed to insert signature data".to_string(),
                }),
            };
        }

        Err(colls.err().unwrap())
    }

    /// Gets signature data from the database
    ///
    /// ### Arguments
    ///
    /// * `message_id` - Message ID to get signature data for
    pub async fn get_signature_data(&self, message_id: String) -> Result<SignatureEntry, DbError> {
        let colls = self.get_collections().await;

        if let Ok((sig_collection, sig_id_collection)) = colls {
            let sig_id: SigId = match sig_id_collection.find_one(doc! { "id": message_id }) {
                Ok(sig_id) => sig_id.unwrap(),
                Err(_) => {
                    return Err(DbError {
                        message: "Failed to find signature id".to_string(),
                    });
                }
            };

            return match sig_collection.find_one(doc! { "pk_hash": sig_id.pk_hash }) {
                Ok(sig_data) => Ok(sig_data.unwrap()),
                Err(_) => Err(DbError {
                    message: "Failed to find signature data".to_string(),
                }),
            };
        }

        Err(colls.err().unwrap())
    }

    /// Creates a signature entry
    ///
    /// ### Arguments
    ///
    /// * `id` - ID of the signature entry
    /// * `passphrase` - Passphrase to derive an encryption key from
    pub fn create_signature_data(&self, id: &str, passphrase: &str) -> SignatureEntry {
        let keypair = gen_keypair();
        let pk_hash = hex::encode(sha3_256::digest(keypair.0.as_ref()));
        let rest_key = self.security.derive_rest_key(id, passphrase);
        let (pub_key, secret_key) = self.security.encrypt_keys_for_storage(rest_key, keypair);

        SignatureEntry {
            pk_hash,
            pub_key,
            secret_key,
            ttl: SIG_TTL,
            timestamp: "".to_string(),
        }
    }

    /// Signs a message with the private key of the public key hash
    ///
    /// ### Arguments
    ///
    /// * `id` - ID of the signature entry
    /// * `passphrase` - Passphrase to derive an encryption key from
    /// * `message` - Message to sign
    pub async fn sign_message(
        &self,
        id: &str,
        passphrase: &str,
        message: Vec<u8>,
    ) -> (Signature, PublicKey) {
        let sig_data = self.get_signature_data(id.to_string()).await.unwrap();
        let rest_key = self.security.derive_rest_key(id, passphrase);
        let (pub_key, secret_key) = self
            .security
            .decrypt_keys_from_storage(rest_key, (sig_data.pub_key, sig_data.secret_key));
        let signature = crate::crypto::sign_ed25519::sign_detached(&message, &secret_key);

        (signature, pub_key)
    }

    /// Verifies a message with the signature
    ///
    /// ### Arguments
    ///
    /// * `id` - ID of the signature entry
    /// * `passphrase` - Passphrase to derive an encryption key from
    /// * `message` - Message to verify
    /// * `signature` - Signature to verify with
    pub async fn verify_message(
        &self,
        id: &str,
        passphrase: &str,
        message: Vec<u8>,
        signature: Signature,
    ) -> bool {
        let sig_data = self.get_signature_data(id.to_string()).await.unwrap();
        let rest_key = self.security.derive_rest_key(id, passphrase);
        let (pub_key, _) = self
            .security
            .decrypt_keys_from_storage(rest_key, (sig_data.pub_key, sig_data.secret_key));

        crate::crypto::sign_ed25519::verify_detached(&signature, &message, &pub_key)
    }
}
