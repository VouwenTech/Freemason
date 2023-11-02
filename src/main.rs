pub mod api;
pub mod crypto;
pub mod db;

use crate::api::routes::*;
use crate::db::secret_db::SecretDb;
use crate::db::sign_db::SignatureDb;
use futures::lock::Mutex;
use std::sync::Arc;
use warp::Filter;

#[tokio::main]
async fn main() {
    let passphrase: String = "test".to_string();
    let sig_db = Arc::new(Mutex::new(SignatureDb::new(
        "data/signatures.db".to_string(),
    )));
    let sec_db = Arc::new(Mutex::new(SecretDb::new("data/secret.db".to_string())));

    let routes = upload_raw(sec_db.clone(), passphrase.clone())
        .or(download(sec_db, passphrase.clone()))
        .or(sign(sig_db.clone(), passphrase.clone()))
        .or(verify(sig_db, passphrase));

    println!("Server running on port 3030");
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}
