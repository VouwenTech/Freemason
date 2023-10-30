use crate::crypto::sign_ed25519::Signature;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct ChunkMetadataPayload {
    pub file_name: String,
    pub chunk_number: usize,
    pub total_chunks: usize,
    pub timestamp: String,
    pub custom_data: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct DownloadParamsPayload {
    pub offset: u64,
    pub file_name: String,
}

#[derive(serde::Deserialize)]
pub struct SigningDataPayload {
    pub id: String,
    pub message: String,
    pub timestamp: String,
    pub signature: Option<Signature>,
    pub custom_data: Option<String>,
}
