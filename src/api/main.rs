use crate::AppState;
use axum::{routing::get, Json, Router};
use serde_json::json;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(self::get::main))
        .route("/test", get(self::get::test))
}

pub mod get {

    use super::*;

    #[axum::debug_handler]
    pub async fn main() -> &'static str {
        "Hello Api"
    }

    #[axum::debug_handler]
    pub async fn test() -> Json<serde_json::Value> {
        Json(json!({
            "name": "John Doe",
            "age": 43,
            "phones": [
                "+44 1234567",
                "+44 2345678"
            ]
        }))
    }
}
