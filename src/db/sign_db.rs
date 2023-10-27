use polodb_core::Database;
use polodb_core::bson::doc;
use serde::{Serialize, Deserialize};
use crate::crypto::asymmetric::sha3_256;
use crate::db::constants::{SIG_COLLECTION, SIG_ID_COLLECTION, SIG_TTL};
use crate::crypto::asymmetric::sign_ed25519::{PublicKey, SecretKey, gen_keypair};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbError {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
    pub pk_hash: String,
    pub keypair: (PublicKey, SecretKey),
    pub ttl: u32,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize)]
struct SigId {
    id: String,
    pk_hash: String,
}

/// Signature database
#[derive(Debug, Clone)]
pub struct SignatureDb {
    url: String
}

impl SignatureDb {

    /// Creates a new signature database
    /// 
    /// ### Arguments
    /// 
    /// * `url` - Database URL
    pub fn new(url: String) -> SignatureDb {
        SignatureDb {
            url
        }
    }

    /// Inserts signature data into the database
    /// 
    /// ### Arguments
    /// 
    /// * `message_id` - Message ID
    /// * `signature_data` - Signature data to insert
    pub async fn insert_signature_data(&self, message_id: String, signature_data: SignatureEntry) -> Result<(), DbError> {
        let db = match Database::open_file(self.url.clone()) {
            Ok(db) => db,
            Err(_) => return Err(DbError { message: "Failed to open database".to_string() })
        
        };
        let sig_collection = db.collection(SIG_COLLECTION);
        let sig_id_collection = db.collection(SIG_ID_COLLECTION);
    
        match sig_id_collection.insert_one(SigId {
            id: message_id,
            pk_hash: signature_data.pk_hash.clone(),
        }) {
            Ok(_) => (),
            Err(_) => return Err(DbError { message: "Failed to insert signature id".to_string() })
        
        };
    
        match sig_collection.insert_one(signature_data) {
            Ok(_) => Ok(()),
            Err(_) => Err(DbError { message: "Failed to insert signature data".to_string() })
        }
    }

    /// Gets signature data from the database
    /// 
    /// ### Arguments
    /// 
    /// * `message_id` - Message ID to get signature data for
    pub async fn get_signature_data(&self, message_id: String) -> Result<SignatureEntry, DbError> {
        let db = match Database::open_file(self.url.clone()) {
            Ok(db) => db,
            Err(_) => return Err(DbError { message: "Failed to open database".to_string() })
        
        };
        let sig_collection = db.collection(SIG_COLLECTION);
        let sig_id_collection = db.collection(SIG_ID_COLLECTION);
    
        let sig_id: SigId = match sig_id_collection.find_one(doc! { "id": message_id }) {
            Ok(sig_id) => sig_id.unwrap(),
            Err(_) => return Err(DbError { message: "Failed to find signature id".to_string() })
        
        };
    
        match sig_collection.find_one(doc! { "pk_hash": sig_id.pk_hash }) {
            Ok(sig_data) => Ok(sig_data.unwrap()),
            Err(_) => Err(DbError { message: "Failed to find signature data".to_string() })
        
        }
    }

    /// Creates a signature entry
    pub fn create_signature_data() -> SignatureEntry {
        let keypair = gen_keypair();
        let pk_hash = hex::encode(sha3_256::digest(keypair.0.as_ref()));
    
        SignatureEntry {
            keypair,
            pk_hash,
            ttl: SIG_TTL,
            timestamp: "".to_string(),
        }
    }
}
