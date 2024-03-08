use crate::{users::AuthUser, utils::json_validatio_errors, AppState};
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

    #[validate(range(min = 18, max = 20))]
    age: u8,

    // #[validate]
    books: Vec<Book>,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct Book {
    #[validate(length(min = 100, message = "Name must be at least 10 characters"))]
    name: String,

    #[validate(range(min = 12, message = "version not valid"))]
    version: u8,
}

// #[debug_handler]
pub async fn jese(_: Messages, Json(mut payload): Json<MyUser>) {
    match payload.validate() {
        Ok(res) => println!("res {:?}", res),
        Err(errs) => {
            json_validatio_errors(errs).await;
        }
    }

    // Trimming
    payload.name = payload.name.trim().to_string();
    payload.books.iter_mut().for_each(|book| {
        book.name = book.name.trim().to_string();
    });

    // validation
    let errs: ValidationErrors = ValidationErrors::new();

    // validation of My user struct
    match payload.validate() {
        Ok(_) => todo!(),
        Err(err) => println!("payload err \n{}", err),
    }

    // validation of -- Books Vec
    for (i, book) in payload.books.iter().enumerate() {
        println!("book after trim {}", book.name);
        match book.validate() {
            Ok(_) => todo!(),
            Err(err) => println!("book -{} : {}", i + 1, err),
        }
    }

    //Json(payload)
}
