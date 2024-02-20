use crate::{users::AuthUser, AppState};
use askama::Template;
use axum::{routing::get, Router};

#[derive(Template)]
#[template(path = "pages/dashboard.html")]
pub struct DashboardTemplate {
    pub title: &'static str,
    pub messages: Option<Vec<String>>,
    pub username: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(self::get::dashboard))
        .route("/t", get(self::get::test))
}

mod get {
    use super::*;

    // #[axum::debug_handler]
    pub async fn dashboard(user: AuthUser) -> DashboardTemplate {
        DashboardTemplate {
            title: "Dashboard",
            messages: None,
            username: user.name,
        }
    }

    pub async fn test(user: AuthUser) -> DashboardTemplate {
        DashboardTemplate {
            title: "Dashboard",
            messages: None,
            username: user.name,
        }
    }
}
