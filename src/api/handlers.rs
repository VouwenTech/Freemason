use warp::{ Reply, Rejection };
use std::io::{ Read, Write, Seek, SeekFrom };
use std::fs::OpenOptions;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use serde_json::json;
use aes_gcm::aead::Aead;
use std::sync::Arc;
use futures::lock::Mutex;
use aes_gcm::aead::generic_array::GenericArray;
use crate::db::sign_db::SignatureDb;
use crate::crypto::asymmetric::sign_ed25519::{ sign_detached, verify_detached };
use super::interfaces::{ ChunkMetadataPayload, DownloadParamsPayload, SigningDataPayload };
use super::utils::retrieve_signing_data_from_db;

const KEY: &[u8; 16] = b"0123456789abcdef"; // Replace with your key
const NONCE: &[u8; 16] = b"0123456789abcdef";

/// Uploads a chunk of byte data to the server
/// 
/// ### Arguments
/// 
/// * `metadata` - Chunk metadata payload
/// * `chunk` - Chunk of byte data
pub async fn handle_upload_raw(
    metadata: ChunkMetadataPayload,
    chunk: bytes::Bytes
) -> Result<impl Reply, Rejection> {
    let key = GenericArray::from_slice(KEY);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(NONCE);

    let encrypted_data = cipher.encrypt(nonce, chunk.as_ref()).unwrap();

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(metadata.file_name)
        .expect("Failed to open or create file");

    file.write_all(&encrypted_data).expect("Failed to write to file");

    Ok(warp::reply::with_status("Chunk received and encrypted", warp::http::StatusCode::OK))
}

/// Downloads a chunk of byte data from the server
/// 
/// ### Arguments
/// 
/// * `params` - Download parameters payload
pub async fn handle_download(params: DownloadParamsPayload) -> Result<impl Reply, Rejection> {
    let key = GenericArray::from_slice(KEY);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(NONCE);

    let mut file = OpenOptions::new()
        .read(true)
        .open(params.file_name)
        .expect("Failed to open file");

    file.seek(SeekFrom::Start(params.offset)).expect("Failed to seek in file");

    let mut encrypted_chunk = vec![0; 2 * 1024 * 1024 + 16]; // 2MB + 16 bytes for GCM tag
    let read_bytes = file.read(&mut encrypted_chunk).expect("Failed to read from file");

    let decrypted_data = cipher.decrypt(nonce, encrypted_chunk[0..read_bytes].as_ref()).unwrap();

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
    message_payload: SigningDataPayload
) -> Result<impl Reply, Rejection> {
    let id = message_payload.id.clone();
    let sig_data = retrieve_signing_data_from_db(signature_db, id).await;

    let signature = sign_detached(message_payload.message.as_bytes(), &sig_data.keypair.1);
    let response =
        json!({
        "signature": signature,
        "public_key": sig_data.keypair.0,
        "message_id": message_payload.id
    });

    Ok(warp::reply::json(&response))
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
    message_payload: SigningDataPayload
) -> Result<impl Reply, Rejection> {
    let id = message_payload.id.clone();
    let sig_data = retrieve_signing_data_from_db(signature_db, id).await;

    let verification = verify_detached(
        &message_payload.signature.unwrap(),
        message_payload.message.as_bytes(),
        &sig_data.keypair.0
    );
    let response =
        json!({
        "verification": verification,
        "message_id": message_payload.id
    });

    Ok(warp::reply::json(&response))
}
