use super::interfaces::{ ChunkMetadataPayload, DownloadParamsPayload, SigningDataPayload };
use crate::crypto::secretbox_chacha20_poly1305::{ open, seal, Key, Nonce };
use crate::db::sign_db::SignatureDb;
use futures::lock::Mutex;
use serde_json::json;
use std::fs::OpenOptions;
use std::io::{ Read, Seek, SeekFrom, Write };
use std::sync::Arc;
use warp::{ Rejection, Reply };

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
    let key = Key::from_slice(KEY).unwrap();
    let nonce = Nonce::from_slice(NONCE).unwrap();
    let encrypted_data = seal(chunk.to_vec(), &nonce, &key).unwrap();

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
    let key = Key::from_slice(KEY).unwrap();
    let nonce = Nonce::from_slice(NONCE).unwrap();

    let mut file = OpenOptions::new()
        .read(true)
        .open(params.file_name)
        .expect("Failed to open file");

    file.seek(SeekFrom::Start(params.offset)).expect("Failed to seek in file");

    let mut encrypted_chunk_window = vec![0; 2 * 1024 * 1024 + 16]; // 2MB + 16 bytes for GCM tag
    let read_bytes = file.read(&mut encrypted_chunk_window).expect("Failed to read from file");
    let encrypted_chunk = &encrypted_chunk_window[0..read_bytes];

    let decrypted_data = open(encrypted_chunk.to_vec(), &nonce, &key).unwrap();
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
    passphrase: String
) -> Result<impl Reply, Rejection> {
    let id = message_payload.id.clone();
    let (signature, pub_key) = signature_db
        .lock().await
        .sign_message(&id, &passphrase, message_payload.message.into()).await;

    let response =
        json!({
        "signature": signature,
        "public_key": pub_key,
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
    message_payload: SigningDataPayload,
    passphrase: String
) -> Result<impl Reply, Rejection> {
    let id = message_payload.id.clone();
    let verification = signature_db
        .lock().await
        .verify_message(&id, &passphrase, message_payload.message.into(), message_payload.signature.unwrap()).await;

    let response =
        json!({
        "verification": verification,
        "message_id": message_payload.id
    });

    Ok(warp::reply::json(&response))
}
