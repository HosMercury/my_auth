use crate::AppState;
use askama::Template;
use axum::{routing::get, Router};
use rust_i18n::locale;

#[derive(Template)]
#[template(path = "pages/dashboard.html")]
pub struct DashboardTemplate {
    title: String,
    username: String,
    locale: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(self::get::dashboard))
        .route("/test", get(self::get::test))
}

pub mod get {
    use crate::users::User;
    use askama_axum::IntoResponse;
    use axum::extract::State;

    use super::*;

    #[axum::debug_handler]
    pub async fn dashboard(auth_user: User) -> DashboardTemplate {
        DashboardTemplate {
            title: "dashboard".to_owned(),
            username: auth_user.name,
            locale: locale().to_string(),
        }
    }

    #[axum::debug_handler]
    pub async fn test(auth_user: User, State(state): State<AppState>) -> impl IntoResponse {
        "hello test".into_response()
    }
}
