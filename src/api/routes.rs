use std::sync::Arc;
use futures::lock::Mutex;
use warp::{Filter, Rejection, Reply};
use crate::db::sign_db::SignatureDb;
use super::handlers::{handle_upload_raw, handle_download, handle_sign, handle_verify};
use super::utils::{post_cors, with_node_component};

/// POST /upload
/// 
/// Uploads a chunk of byte data to the server
pub fn upload_raw() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("upload"))
        .and(warp::body::json())
        .and(warp::body::bytes())
        .and_then(move |metadata, chunk| handle_upload_raw(metadata, chunk))
        .with(post_cors())
}

/// POST /download
/// 
/// Downloads a chunk of byte data from the server
pub fn download() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("download"))
        .and(warp::body::json())
        .and_then(move |params| handle_download(params))
        .with(post_cors())
}

/// POST /sign
/// 
/// Signs a message with the private key of the public key hash
pub fn sign(sig_db: Arc<Mutex<SignatureDb>>) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("sign"))
        .and(with_node_component(sig_db))
        .and(warp::body::json())
        .and_then(move |db, signing_data| handle_sign(db, signing_data))
        .with(post_cors())
}

/// POST /verify
/// 
/// Verifies a message with the signature
pub fn verify(sig_db: Arc<Mutex<SignatureDb>>) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("verify"))
        .and(with_node_component(sig_db))
        .and(warp::body::json())
        .and_then(move |db, signing_data| handle_verify(db, signing_data))
        .with(post_cors())
}