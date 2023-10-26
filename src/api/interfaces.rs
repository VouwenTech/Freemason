use serde::Deserialize;

#[derive(Deserialize)]
pub struct ChunkMetadata {
    file_name: String,
    chunk_number: usize,
    total_chunks: usize,
    timestamp: String,
    custom_data: Option<String>,
}