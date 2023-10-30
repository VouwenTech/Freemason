pub struct SecretEntry {
    file_name: String,
    total_chunks: usize,
    key: Key,
    nonce: Nonce
}

#[derive(Debug, Clone)]
pub struct SecretDb {
    url: String,
}

impl SecretDb {
    pub fn new(url: String) -> SecretDb {
        SecretDb { url }
    }

    
}