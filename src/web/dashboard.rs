use crate::utils::validation_errs;
use crate::{users::AuthUser, AppState};
use askama::Template;
use axum::{
    routing::{get, post},
    Json, Router,
};
use axum_messages::Messages;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationErrors};

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

    #[validate(range(min = 2000, message = "version not valid"))]
    version: u8,
}

// #[debug_handler]
pub async fn jese(_: Messages, Json(payload): Json<MyUser>) -> Json<MyUser> {
    let res = payload.validate();
    let mut new_errs = ValidationErrors::new();

    match res {
        Ok(res) => println!("res {:?}", res),
        Err(errs) => {
            // flash_errors(errs, messages).await;
            let e = validation_errs(&errs, &mut new_errs);
            println!("{:#?}", e);
        }
    }

    Json(payload)
}
