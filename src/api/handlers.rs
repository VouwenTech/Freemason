use super::interfaces::{ChunkMetadataPayload, DownloadParamsPayload, SigningDataPayload};
use crate::crypto::secretbox_chacha20_poly1305::{open, seal, Key, Nonce};
use crate::crypto::sign_ed25519::Signature;
use crate::db::secret_db::SecretDb;
use crate::db::sign_db::SignatureDb;
use crate::db::DbError;
use futures::lock::Mutex;
use serde_json::json;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::SystemTime;
use warp::{Rejection, Reply};

/// Responds to a 'ping' request with a 'pong' response
///
pub async fn handle_ping() -> Result<impl Reply, Rejection> {
    Ok(warp::reply::with_status("pong", warp::http::StatusCode::OK))
}

/// Responds to a 'health' ping request with a "healthy" status and the server's uptime in seconds
///
pub async fn handle_health() -> Result<impl Reply, Rejection> {
    let uptime = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).
                        expect("System time before UNIX_EPOCH").as_secs();
    let response = json!({
        "status": "healthy",
        "uptime": uptime
    });

    Ok(warp::reply::json(&response))
}


/// Uploads a chunk of byte data to the server
///
/// ### Arguments
///
/// * `metadata` - Chunk metadata payload
/// * `chunk` - Chunk of byte data
pub async fn handle_upload_raw(
    metadata: ChunkMetadataPayload,
    chunk: bytes::Bytes,
    secret_db: Arc<Mutex<SecretDb>>,
    passphrase: String,
) -> Result<impl Reply, Rejection> {
    let key = Key::new();
    let nonce = Nonce::new();
    let sec_db_lock = secret_db.lock().await;
    let encrypted_data = seal(chunk.to_vec(), &nonce, &key).unwrap();

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(metadata.file_name.clone())
        .expect("Failed to open or create file");

    file.write_all(&encrypted_data)
        .expect("Failed to write to file");

    // Save secret entry to DB
    let sec_entry = sec_db_lock.create_secret_entry(
        &metadata.file_name,
        &passphrase,
        metadata.total_chunks,
        (key, nonce),
    );

    match sec_db_lock.insert_secret(sec_entry).await {
        Ok(_) => Ok(warp::reply::with_status(
            "Chunk received and encrypted",
            warp::http::StatusCode::OK,
        )),
        Err(e) => Err(warp::reject::custom(e)),
    }
}

/// Downloads a chunk of byte data from the server
///
/// ### Arguments
///
/// * `params` - Download parameters payload
pub async fn handle_download(
    params: DownloadParamsPayload,
    secret_db: Arc<Mutex<SecretDb>>,
    passphrase: String,
) -> Result<impl Reply, Rejection> {
    let sec_db_lock = secret_db.lock().await;
    let sec_entry = match sec_db_lock.get_secret(&params.file_name, &passphrase).await {
        Ok(entry) => entry,
        Err(e) => return Err(warp::reject::custom(e)),
    };

    let mut file = OpenOptions::new()
        .read(true)
        .open(params.file_name)
        .expect("Failed to open file");

    file.seek(SeekFrom::Start(params.offset))
        .expect("Failed to seek in file");

    let mut encrypted_chunk_window = vec![0; 2 * 1024 * 1024 + 16]; // 2MB + 16 bytes for GCM tag
    let read_bytes = file
        .read(&mut encrypted_chunk_window)
        .expect("Failed to read from file");
    let encrypted_chunk = &encrypted_chunk_window[0..read_bytes];

    let decrypted_data = open(encrypted_chunk.to_vec(), &sec_entry.nonce, &sec_entry.key).unwrap();
    let is_last_chunk = read_bytes < encrypted_chunk.len();

    let response = json!({
        "data": decrypted_data,
        "isLastChunk": is_last_chunk
    });

    Ok(warp::reply::json(&response))
}

/// Signs a message with a newly generated public/private keypair
///
/// ### Arguments
///
/// * `signature_db` - Signature database
/// * `message_payload` - Message payload
pub async fn handle_sign(
    signature_db: Arc<Mutex<SignatureDb>>,
    message_payload: SigningDataPayload,
    passphrase: String,
) -> Result<impl Reply, Rejection> {
    let id = message_payload.id.clone();
    let sign_option = signature_db
        .lock()
        .await
        .sign_message(&id, &passphrase, message_payload.message.into())
        .await;
    if let Some((signature, pub_key)) = sign_option {
        let hex_sig = hex::encode(signature);

        let response = json!({
            "signature": hex_sig,
            "public_key": pub_key,
            "message_id": message_payload.id
        });

        return Ok(warp::reply::json(&response));
    }

    Err(warp::reject::custom(DbError {
        message: "Failed to sign message".to_string(),
    }))
}

/// Verifies a message with the provided signature
///
/// TODO: Add for case where signature data is not present in the DB, so allow for
/// the payload to include a public key and verify with that as a default
///
/// ### Arguments
///
/// * `signature_db` - Signature database
/// * `message_payload` - Message payload
pub async fn handle_verify(
    signature_db: Arc<Mutex<SignatureDb>>,
    message_payload: SigningDataPayload,
    passphrase: String,
) -> Result<impl Reply, Rejection> {
    let id = message_payload.id.clone();
    let sig = match message_payload.signature {
        Some(sig) => match Signature::from_slice(&hex::decode(sig).unwrap()) {
            Some(sig) => sig,
            None => {
                return Err(warp::reject::custom(DbError {
                    message: "Failed to decode signature".to_string(),
                }));
            }
        },
        None => {
            return Err(warp::reject::custom(DbError {
                message: "Signature not provided".to_string(),
            }));
        }
    };

    let verification = signature_db
        .lock()
        .await
        .verify_message(&id, &passphrase, message_payload.message.into(), sig)
        .await;

    let response = json!({
        "verification": verification,
        "message_id": message_payload.id
    });

    Ok(warp::reply::json(&response))
}