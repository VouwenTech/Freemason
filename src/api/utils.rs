use std::convert::Infallible;
use warp::Filter;
use serde_json::json;
use std::process::Command;

/// Fetch or calculate the service status information
/// and encode it into JSON format.
pub fn fetch_service_status() -> String {
    let output = Command::new("systemctl")
                    .arg("status")
                    .output()
                    .expect("Failed to fetch service status");
    let status = String::from_utf8_lossy(&output.stdout).to_string();

    // Encode the status to JSON format
    let json = json!({
        "Service Status": status
    });

    json.to_string()
}

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
        .allow_methods(vec!["POST", "OPTIONS"])
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
        .allow_methods(vec!["GET", "OPTIONS"])
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