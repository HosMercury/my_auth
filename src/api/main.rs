use crate::AppState;
use axum::{routing::get, Router};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(self::get::main))
        .route("/test", get(self::get::test))
}

pub mod get {
    use crate::web::keygen::os_keygen;

    #[axum::debug_handler]
    pub async fn main() -> &'static str {
        "Hello Api"
    }

    #[axum::debug_handler]
    pub async fn test() -> String {
        os_keygen().await
    }
}
