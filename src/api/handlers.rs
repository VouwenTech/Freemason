use warp::{Reply, Rejection};
use std::fs::OpenOptions;
use std::io::Write;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;
use super::interfaces::ChunkMetadata;

const KEY: &[u8; 16] = b"0123456789abcdef";  // Replace with your key
const NONCE: &[u8; 16] = b"0123456789abcdef";

pub async fn handle_upload_raw(metadata: ChunkMetadata, chunk: bytes::Bytes) -> Result<impl Reply, Rejection> {
    let key = GenericArray::from_slice(KEY);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(NONCE);

    let encrypted_data = cipher.encrypt(nonce, chunk.as_ref()).unwrap();

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("encrypted_data.bin")
        .expect("Failed to open or create file");

    file.write_all(&encrypted_data).expect("Failed to write to file");

    Ok(warp::reply::with_status("Chunk received and encrypted", warp::http::StatusCode::OK))
}