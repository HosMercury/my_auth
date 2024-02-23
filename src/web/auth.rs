use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::State,
    middleware,
    response::Redirect,
    routing::{get, post},
    Form, Router,
};
use axum_messages::Messages;
use std::borrow::Cow;
use tower_sessions::Session;
use validator::Validate;

use crate::utils::validation_errs;

use crate::users::{Credentials, PasswordCreds, SignUp, User};
use crate::{utils, AppState};

pub const USER_SESSION_KEY: &str = "user";

#[derive(Template)]
#[template(path = "pages/signin.html")]
pub struct SigninTemplate {
    pub title: &'static str,
    pub messages: Option<Vec<String>>,
}

#[derive(Template)]
#[template(path = "pages/signup.html")]
pub struct SignupTemplate {
    pub title: &'static str,
    pub messages: Option<Vec<String>>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/signup", get(self::get::signup).post(self::post::signup))
        .route("/signin", get(self::get::signin).post(self::post::password))
        .layer(middleware::from_fn(utils::is_authenticated_middlware))
        .route("/signout", post(self::post::signout))
}

mod get {
    use super::*;

    pub async fn signin() -> SigninTemplate {
        SigninTemplate {
            title: "Sign in",
            messages: None,
        }
    }

    pub async fn signup(messages: Messages) -> SignupTemplate {
        let messages = messages
            .into_iter()
            .map(|message| format!("{}: {}", message.level, message))
            .collect::<Vec<_>>();

        SignupTemplate {
            title: "Sign up",
            messages: Some(messages),
        }
    }
}

mod post {
    use super::*;

    pub async fn signup(
        mut messages: Messages,
        State(AppState { db, .. }): State<AppState>,
        Form(signup_data): Form<SignUp>,
    ) -> impl IntoResponse {
        match signup_data.validate() {
            Ok(_) => {
                // save user to db
                Redirect::to("/")
            }
            Err(errs) => {
                validation_errs(errs).iter().for_each(|(_, err_value)| {
                    let m = err_value
                        .clone()
                        .message
                        .unwrap_or(Cow::Borrowed("Unknown validation error"));

                    // you just clone messages for each iteration of the loop
                    messages = messages.clone().error(m.to_string());
                });

                println!("{:#?}", messages.clone());
                Redirect::to("/signup")
            }
        }
    }

    pub async fn password(
        session: Session,
        State(AppState { db, client }): State<AppState>,
        Form(creds): Form<PasswordCreds>,
    ) -> impl IntoResponse {
        match User::authenticate(Credentials::Password(creds.clone()), db, client, session).await {
            Ok(Some(_)) => Redirect::to("/").into_response(),
            Ok(None) => Redirect::to("/signin").into_response(),
            Err(_) => Redirect::to("/signin").into_response(),
        }
    }

    pub async fn signout(session: Session) -> Redirect {
        session.flush().await.unwrap();
        Redirect::to("/signin")
    }
}
