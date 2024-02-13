use crate::{models::user::Credentials, AppState};
use askama::Template;
use axum::{
    response::IntoResponse,
    routing::{get, post},
    Form, Router,
};
use axum_messages::{Message, Messages};
use serde::Deserialize;

pub fn router() -> Router<AppState> {
    Router::new().route("/login", get(login).post(post_login))
}

#[derive(Template)]
#[template(path = "auth/login.html.j2")]
pub struct LoginTemplate {
    title: &'static str,
    messages: Vec<Message>,
}

async fn login(messages: Messages) -> LoginTemplate {
    LoginTemplate {
        title: "Login",
        messages: messages.into_iter().collect(),
    }
}

async fn post_login(Form(creds): Form<Credentials>) {
    let username = creds.username;
    let password = creds.password;
}
