use crate::{users::AuthUser, utils::flash_errors, AppState};
use askama::Template;
use axum::{
    routing::{get, post},
    Json, Router,
};
use axum_messages::Messages;
use serde::{Deserialize, Serialize};
use validator::Validate;

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
        .route("/jese", post(jese))
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

#[derive(Serialize, Deserialize, Validate)]
pub struct MyUser {
    #[validate(length(min = 100, message = "Name must be at least 10 characters"))]
    name: String,
    age: u8,

    #[validate]
    books: Vec<Book>,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct Book {
    #[validate(length(min = 100, message = "Name must be at least 10 characters"))]
    book_name: String,

    #[validate(range(min = 12, message = "version not valid"))]
    version: u8,
}

// #[debug_handler]
pub async fn jese(messages: Messages, Json(payload): Json<MyUser>) -> Json<MyUser> {
    match payload.validate() {
        Ok(res) => println!("res {:?}", res),
        Err(errs) => {
            flash_errors(errs, messages).await;
        }
    }

    Json(payload)
}
