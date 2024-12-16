```rust
use warp::http::Method;
use warp::Filter;

// Prepare a set of allowed origins for CORS
fn setup_cors() -> warp::filters::cors::Builder {
    let allowed_origins = vec!["http://localhost:3000", "https://example.com"];

    warp::cors().allow_origins(allowed_origins)
}

// Set up OPTIONS method handling
pub fn options() -> impl Filter<Extract = (String,), Error = warp::Rejection> + Clone {
    warp::options()
        .and(warp::header("Origin"))
        .and(warp::header("Access-Control-Request-Method"))
        .map(|origin: String, method: Method| {
            let cors = setup_cors();
            let reply = warp::reply()
                .with_header("Access-Control-Allow-Origin", origin)
                .with_header("Access-Control-Allow-Methods", method.as_str());

            if cors.is_allowed_origin(&origin) {
                warp::reply::with_status(reply, warp::http::StatusCode::OK)
            } else {
                warp::reply::with_status(reply, warp::http::StatusCode::FORBIDDEN)
            }
        })
}

// The handler function for OPTIONS requests
pub fn handle_options() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    options().and_then(move |_origin, _req_method| {
        let reply = warp::reply();

        let response = warp::http::Response::builder()
            .status(warp::http::StatusCode::OK)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            .body(reply)
            .unwrap();

        Ok(response)
    })
}
```