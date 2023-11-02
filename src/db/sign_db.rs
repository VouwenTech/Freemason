use super::security::SecurityAtRest;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{gen_keypair, PublicKey, Signature};
use crate::db::constants::SIG_TTL;
use crate::db::DbError;
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
        let db = match sled::open(self.url.clone()) {
            Ok(db) => db,
            Err(_) => {
                return Err(DbError {
                    message: "Failed to open database".to_string(),
                });
            }
        };

        println!("Inserting signature data into the collection");

        // Inserting the SigId
        let sig_id_json = serde_json::json!(SigId {
            id: message_id.clone(),
            pk_hash: signature_data.pk_hash.clone(),
        });
        let sig_id = serde_json::to_vec(&sig_id_json).unwrap();
        db.insert(message_id, sig_id).unwrap();

        println!("Inserting full signature into the db");

        // Insert SignatureData
        let sig_data_json = serde_json::json!(signature_data);
        let sig_data = serde_json::to_vec(&sig_data_json).unwrap();
        db.insert(signature_data.pk_hash, sig_data).unwrap();

        Ok(())
    }

    /// Gets signature data from the database
    ///
    /// ### Arguments
    ///
    /// * `message_id` - Message ID to get signature data for
    pub async fn get_signature_data(&self, message_id: String) -> Result<SignatureEntry, DbError> {
        let db = match sled::open(self.url.clone()) {
            Ok(db) => db,
            Err(e) => {
                println!("Error: {}", e);
                println!("URL: {}", self.url.clone());
                return Err(DbError {
                    message: "Failed to open database".to_string(),
                });
            }
        };

        let sig_id: SigId = match db.get(&message_id) {
            Ok(Some(sig_id_raw)) => serde_json::from_slice(&sig_id_raw).unwrap(),
            Ok(None) => {
                println!("No value found for key");
                return Err(DbError {
                    message: "No value found for key".to_string(),
                });
            }
            Err(e) => {
                println!("Error: {}", e);
                return Err(DbError {
                    message: "Failed to get value from database".to_string(),
                });
            }
        };

        match db.get(&sig_id.pk_hash) {
            Ok(Some(sig_data)) => {
                let sig_data: SignatureEntry = serde_json::from_slice(&sig_data).unwrap();
                Ok(sig_data)
            }
            Ok(None) => {
                println!("No value found for key");
                return Err(DbError {
                    message: "No value found for key".to_string(),
                });
            }
            Err(e) => {
                println!("Error: {}", e);
                return Err(DbError {
                    message: "Failed to get value from database".to_string(),
                });
            }
        }
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
    ) -> Option<(Signature, PublicKey)> {
        let sig_data = match self.get_signature_data(id.to_string()).await {
            Ok(sig_data) => sig_data,
            Err(_) => {
                let sig_data = self.create_signature_data(id, passphrase);

                match self
                    .insert_signature_data(id.to_string(), sig_data.clone())
                    .await
                {
                    Ok(_) => sig_data,
                    Err(e) => {
                        println!("Error: {:?}", e);
                        panic!("Failed to insert signature data");
                    }
                }
            }
        };

        println!("Now deriving rest key and continuing");

        let rest_key = self.security.derive_rest_key(id, passphrase);
        if let Some((pub_key, secret_key)) = self
            .security
            .decrypt_keys_from_storage(rest_key, (sig_data.pub_key, sig_data.secret_key))
        {
            let signature = crate::crypto::sign_ed25519::sign_detached(&message, &secret_key);

            return Some((signature, pub_key));
        }

        None
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

        if let Some((pub_key, _)) = self
            .security
            .decrypt_keys_from_storage(rest_key, (sig_data.pub_key, sig_data.secret_key))
        {
            return crate::crypto::sign_ed25519::verify_detached(&signature, &message, &pub_key);
        }

        false
    }
}
