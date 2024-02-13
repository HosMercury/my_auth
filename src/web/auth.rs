use crate::web::app::AppState;
use axum::{routing::get, Router};

pub fn router() -> Router<AppState> {
    Router::new().route("/login", get(login))
}

pub async fn login() {
    //
}
