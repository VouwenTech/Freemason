use actix_cors::Cors;
use actix_web::{http::header, web, App, HttpRequest, HttpResponse, HttpServer, Result};

// Create middleware for CORS settings
pub fn cors_middleware() -> Cors {
    Cors::permissive()
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
        .allowed_header(header::CONTENT_TYPE)
        .max_age(3600)
}

// Function to handle preflight request
pub async fn preflight(_req: HttpRequest) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().finish())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cors_middleware_test() {
        let cors = cors_middleware();
        assert!(cors.allowed_origin().is_any());
        assert_eq!(cors.allowed_methods().len(), 5);
        assert!(cors.allowed_methods().contains("OPTIONS"));
    }
}
