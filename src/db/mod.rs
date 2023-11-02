pub mod constants;
pub mod secret_db;
pub mod security;
pub mod sign_db;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DbError {
    pub message: String,
}

impl warp::reject::Reject for DbError {}
