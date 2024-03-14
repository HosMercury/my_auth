use crate::AppState;
use axum::{routing::get, Router};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(self::get::main))
        .route("/test", get(self::get::test))
}

pub mod get {
    use base64::prelude::*;
    use rand_core::{OsRng, RngCore};

    #[axum::debug_handler]
    pub async fn main() -> &'static str {
        "Hello Api"
    }

    #[axum::debug_handler]
    pub async fn test() -> String {
        let mut key = [0u8; 64];
        OsRng.fill_bytes(&mut key);
        let random_u64 = OsRng.next_u64();

        let token = BASE64_URL_SAFE_NO_PAD.encode(&random_u64.to_string());

        token
    }
}
