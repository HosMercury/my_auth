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
    Router::new().route("/", get(dashboard)).route("/t", get(t))
}

#[axum::debug_handler]
pub async fn dashboard(user: AuthUser) -> DashboardTemplate {
    println!("dashboard");

    println!("user: {:?}", user.name);

    DashboardTemplate {
        title: "Dashboard",
        messages: None,
        username: "Hos".to_string(),
    }
}

pub async fn t() -> DashboardTemplate {
    DashboardTemplate {
        title: "Dashboard",
        messages: None,
        username: "Hos".to_string(),
    }
}
