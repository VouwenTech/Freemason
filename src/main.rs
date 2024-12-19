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
    let sig_db = Arc::new(Mutex::new(SignatureDb::new("db/signatures".to_string())));
    let sec_db = Arc::new(Mutex::new(SecretDb::new("db/secret".to_string())));

    let service_status = warp::path("service-status").map(move || handlers::service_status(())).boxed();

    let routes = upload_raw(sec_db.clone(), passphrase.clone())
        .or(download(sec_db.clone(), passphrase.clone()))
        .or(sign(sig_db.clone(), passphrase.clone()))
        .or(verify(sig_db.clone(), passphrase.clone()))
        .or(service_status);

    println!("Server running on port 3030");
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}