use crate::AppState;
use axum::routing::post;
use axum::Router;

pub fn router() -> Router<AppState> {
    Router::new().route("/register", post(self::post::client_register))
}

mod get {}

mod post {
    use axum::extract::State;

    use crate::AppState;

    // #[debug_handler]
    pub async fn client_register(State(AppState { db, .. }): State<AppState>) -> &'static str {
        ""
    }
}
