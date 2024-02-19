use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::State;
use axum::response::Redirect;
use axum::routing::post;
use axum::{routing::get, Form, Router};
use tower_sessions::Session;

use crate::users::{Credentials, PasswordCreds, User};
use crate::AppState;

pub const USER_SESSION_KEY: &str = "user";

#[derive(Template)]
#[template(path = "pages/login.html")]
pub struct LoginTemplate {
    pub title: &'static str,
    pub messages: Option<Vec<String>>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", get(login).post(password))
        .route("/logout", post(logout))
}

pub async fn login() -> LoginTemplate {
    LoginTemplate {
        title: "Login",
        messages: None,
    }
}

pub async fn password(
    session: Session,
    State(AppState { db, client }): State<AppState>,
    Form(creds): Form<PasswordCreds>,
) -> impl IntoResponse {
    match User::authenticate(Credentials::Password(creds.clone()), db, client, session).await {
        Ok(Some(_)) => Redirect::to("/").into_response(),
        Ok(None) => Redirect::to("/login").into_response(),
        Err(_) => Redirect::to("/login").into_response(),
    }
}

pub async fn logout(session: Session) -> Redirect {
    session.flush().await.unwrap();
    Redirect::to("/login")
}
