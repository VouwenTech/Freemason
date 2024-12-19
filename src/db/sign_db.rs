use super::security::SecurityAtRest;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{gen_keypair, PublicKey, Signature};
use crate::db::constants::SIG_TTL;
use crate::db::DbError;
use serde::{Deserialize, Serialize};

/// Data for signing, pub/priv keypair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningEntry {
    pub pk_hash: String,
    pub pub_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub ttl: u32,
    pub timestamp: String,
}

/// Identifier for a signing entry
#[derive(Serialize, Deserialize)]
pub struct SigningId {
    pub id: String,
    pub pk_hash: String,
}

/// Database for signing
#[derive(Debug, Clone)]
pub struct SigningDb {
    url: String,
    security: SecurityAtRest,
}

impl SigningDb {
    /// Creates a new signing database
    ///
    /// ### Arguments
    ///
    /// * `url` - Database URL
    pub fn new(url: String) -> SigningDb {
        SigningDb{
            url,
            security: SecurityAtRest::new(),
        }
    }

    /// Inserts signature data into the database
    ///
    /// ### Arguments
    ///
    /// * `message_id` - Message ID
    /// * `signing_data` - Signature data to insert
    pub async fn insert(&self, message_id: String, signing_data: SigningEntry) -> Result<(), DbError> {
        
        // code omitted for brevity
        
        // Inserting full signing data
        let signing_data_json = serde_json::json!(signing_data);
        let signing_data = serde_json::to_vec(&signing_data_json).unwrap();
        db.insert(signing_data.pk_hash, signing_data).unwrap();

        Ok(())
    }

    /// Gets signature data from the database
    ///
    /// ### Arguments
    ///
    /// * `message_id` - Message ID to get signature data for
    pub async fn get(&self, message_id: String) -> Result<SigningEntry, DbError> {
        
        // code omitted for brevity

        Ok(signing_data)
    }

    /// Creates a signing entry
    ///
    /// ### Arguments
    ///
    /// * `id` - ID of the signing entry
    /// * `passphrase` - Passphrase to derive an encryption key from
    pub fn create(&self, id: &str, passphrase: &str) -> SigningEntry {
        
        // code omitted for brevity

        SigningEntry {
            pk_hash,
            pub_key,
            secret_key,
            ttl: SIG_TTL,
            timestamp: "".to_string(),
        }
    }

    /// Signs a message
    ///
    /// ### Arguments
    ///
    /// * `id` - ID of the signing entry
    /// * `passphrase` - Passphrase to derive an encryption key from
    /// * `message` - Message to sign
    pub async fn sign(&self, id: &str, passphrase: &str, message: Vec<u8>) -> Option<(Signature, PublicKey)> {
    
        // code omitted for brevity

        None
    }

    /// Verifies a message with the signature
    ///
    /// ### Arguments
    ///
    /// * `id` - ID of the signing entry
    /// * `passphrase` - Passphrase to derive an encryption key from
    /// * `message` - Message to verify
    /// * `signature` - Signature to verify with
    pub async fn verify(&self, id: &str, passphrase: &str, message: Vec<u8>, signature: Signature) -> bool {

        // code omitted for brevity

        false
    }
}