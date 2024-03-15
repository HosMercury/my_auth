use crate::AppState;
use axum::{routing::get, Router};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(self::get::main))
        .route("/test", get(self::get::test))
}

pub mod get {
    use crate::web::os_key_gen;

    #[axum::debug_handler]
    pub async fn main() -> &'static str {
        "Hello Api"
    }

    #[axum::debug_handler]
    pub async fn test() -> String {
        os_key_gen().await
    }
}
