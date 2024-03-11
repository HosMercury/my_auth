use crate::{users::AuthUser, AppState};
use askama::Template;
use axum::{routing::get, Router};
use rust_i18n::locale;

#[derive(Template)]
#[template(path = "pages/dashboard.html")]
pub struct DashboardTemplate {
    pub title: String,
    pub messages: Option<Vec<String>>,
    pub username: String,
    pub locale: String,
}

impl DashboardTemplate {
    pub async fn new(
        title: String,
        messages: Option<Vec<String>>,
        username: String,
        locale: String,
    ) -> Self {
        DashboardTemplate {
            title: t!(&title).to_string(),
            messages,
            username,
            locale,
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(self::get::dashboard))
        .route("/t", get(self::get::test))
    //.route("/jese", post(jese))
}

pub mod get {
    use super::*;

    // #[axum::debug_handler]
    pub async fn dashboard(user: AuthUser) -> DashboardTemplate {
        DashboardTemplate::new(
            "dashboard".to_owned(),
            None,
            user.name,
            locale().to_string(),
        )
        .await
    }

    pub async fn test(user: AuthUser) -> DashboardTemplate {
        DashboardTemplate::new(
            "dashboard".to_owned(),
            None,
            user.name,
            locale().to_string(),
        )
        .await
    }
}

// #[derive(Serialize, Deserialize, Validate)]
// pub struct MyUser {
//     #[validate(length(code = "min_length", min = 100))]
//     name: String,

//     #[validate(range(min = 18, max = 20))]
//     age: u8,

//     // #[validate]
//     books: Vec<Book>,
// }

// #[derive(Serialize, Deserialize, Validate)]
// pub struct Book {
//     #[validate(length(code = "min_length", min = 100))]
//     name: String,

//     #[validate(range(min = 12))]
//     version: u8,
// }

// #[debug_handler]
// pub async fn jese(_: Messages, Json(mut payload): Json<MyUser>) -> Json<MyUser> {
//     rust_i18n::set_locale("ar");

//     match payload.validate() {
//         Ok(res) => println!("res {:?}", res),
//         Err(errs) => {
//             let errs = validation_errors(&errs).await;
//             println!("JESE validation errs \n{:#?}", errs);
//         }
//     }

//     // Trimming
//     payload.name = payload.name.trim().to_string();
//     payload.books.iter_mut().for_each(|book| {
//         book.name = book.name.trim().to_string();
//     });

//     // validation
//     let mut errs: ValidationErrors = ValidationErrors::new();

//     // validation of My user struct
//     match payload.validate() {
//         Ok(_) => todo!(),
//         Err(ـ) => {
//             //println!("{}", err);
//         }
//     }

//     // validation of -- Books Vec
//     for (i, book) in payload.books.iter().enumerate() {
//         match book.validate() {
//             Ok(_) => todo!(),
//             Err(errors) => {
//                 let errors = flatten_validation_errs(&errors, &mut errs);

//                 for (field, errs) in errors.field_errors().into_iter() {
//                     errs.iter().for_each(|e| {
//                         // println!("{:?}", e.params);
//                     });
//                 }
//             }
//         }
//     }

//     Json(payload)
// }
