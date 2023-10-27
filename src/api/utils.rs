use std::convert::Infallible;
use warp::Filter;
use std::sync::Arc;
use futures::lock::Mutex;
use crate::db::sign_db::{SignatureDb, SignatureEntry};

/// Easy and simple POST CORS
pub fn post_cors() -> warp::cors::Builder {
    warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "Accept",
            "User-Agent",
            "Sec-Fetch-Mode",
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Headers",
            "Content-Type",
        ])
        .allow_methods(vec!["POST"])
}

/// Easy and simple GET CORS
pub fn get_cors() -> warp::cors::Builder {
    warp::cors()
        .allow_any_origin()
        .allow_headers(vec![
            "Accept",
            "User-Agent",
            "Sec-Fetch-Mode",
            "Referer",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Headers",
            "Content-Type",
        ])
        .allow_methods(vec!["GET"])
}

/// Clone component/struct to use in route
///
/// ### Arguments
///
/// * `comp` - Component/struct to clone
pub fn with_node_component<T: Clone + Send>(
    comp: T,
) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
    warp::any().map(move || comp.clone())
}

pub async fn retrieve_signing_data_from_db(db: Arc<Mutex<SignatureDb>>, id: String) -> SignatureEntry {
    match db.lock().await.get_signature_data(id.clone()).await {
        Ok(sig_data) => sig_data,
        Err(_) => {
            let sd = SignatureDb::create_signature_data();
            let _ = db.lock().await.insert_signature_data(id.clone(), sd.clone());

            sd
        }
    }
}