use warp::{Filter, Rejection, Reply};
use super::handlers::handle_upload_raw;
use super::utils::post_cors;

pub fn raw_upload() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::post()
        .and(warp::path("upload"))
        .and(warp::body::json())
        .and(warp::body::bytes())
        .and_then(move |metadata, chunk| handle_upload_raw(metadata, chunk))
        .with(post_cors())
}