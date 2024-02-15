use askama::Template;
use axum::extract::State;
use axum::http::StatusCode;
use axum::{extract::Query, routing::get, Form, Router};
use serde::Deserialize;

use crate::users::{Credentials, PasswordCreds, User};
use crate::AppState;

#[derive(Template)]
#[template(path = "auth/login.html.j2")]
pub struct LoginTemplate {
    pub title: &'static str,
    pub messages: Option<Vec<String>>,
    pub next: Option<String>,
}

// This allows us to extract the "next" field from the query string. We use this
// to redirect after log in.
#[derive(Debug, Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/login", get(login).post(password))
}

pub async fn login(Query(NextUrl { next }): Query<NextUrl>) -> (StatusCode, LoginTemplate) {
    (
        StatusCode::OK,
        LoginTemplate {
            title: "Login",
            messages: None,
            next,
        },
    )
}

pub async fn password(
    State(AppState { db, client }): State<AppState>,
    Form(creds): Form<PasswordCreds>,
) {
    let user = User::authenticate(Credentials::Password(creds.clone()), db, client).await;
}
