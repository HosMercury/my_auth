use crate::{users::AuthUser, web::auth::USER_SESSION_KEY};
use askama_axum::IntoResponse;
use axum::{
    async_trait,
    extract::{FromRequestParts, Request},
    http::request::Parts,
    middleware::Next,
    response::Redirect,
    response::Response,
};
use lazy_static::lazy_static;
use regex::Regex;
use sqlx::{query, Pool, Postgres};
use std::collections::HashMap;
use tower_sessions::Session;
use validator::{ValidationError, ValidationErrorsKind};

////////////////////////////////////////////////////////////////////////
////////////////////////// Validators //////////////////////////////////
lazy_static! {
    pub static ref REGEX_USERNAME: Regex = Regex::new(r"^[a-zA-Z0-9_-]{4,50}$").unwrap();
}

pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    let mut has_whitespace = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;

    for c in password.chars() {
        has_whitespace |= c.is_whitespace();
        has_lower |= c.is_lowercase();
        has_upper |= c.is_uppercase();
        has_digit |= c.is_ascii_digit();
    }

    if !has_whitespace && has_upper && has_lower && has_digit && password.len() >= 8 {
        Ok(())
    } else {
        Err(ValidationError::new("Password Validation Failed"))
    }
}

pub async fn username_exists(username: &str, pool: &Pool<Postgres>) -> bool {
    query!("SELECT username FROM users WHERE username = $1", username)
        .fetch_one(pool)
        .await
        .is_ok()
}

pub async fn email_exists(email: &str, pool: &Pool<Postgres>) -> bool {
    query!("SELECT email FROM users WHERE email = $1", email)
        .fetch_one(pool)
        .await
        .is_ok()
}

pub fn extract_errors(
    errors: &HashMap<&'static str, ValidationErrorsKind>,
) -> HashMap<String, String> {
    let mut extracted_errs: HashMap<String, String> = HashMap::new();
    for (k, v) in errors {
        match v {
            ValidationErrorsKind::Struct(_) => todo!(),
            ValidationErrorsKind::List(_) => {}
            ValidationErrorsKind::Field(errs) => {
                for err in errs {
                    let msg = err.message.as_ref().unwrap();
                    extracted_errs.insert(k.to_string(), msg.to_string());
                }
            }
        }
    }
    extracted_errs
}

////////////////////////////////////////////////////////////////////////
////////////////////////// Midlewares //////////////////////////////////
pub async fn auth_middlware(session: Session, request: Request, next: Next) -> Response {
    match session.get::<AuthUser>(USER_SESSION_KEY).await.unwrap() {
        Some(_) => next.run(request).await,
        None => Redirect::to("/signin").into_response(),
    }
}

pub async fn is_authenticated_middlware(
    session: Session,
    request: Request,
    next: Next,
) -> Response {
    match session.get::<AuthUser>(USER_SESSION_KEY).await.unwrap() {
        Some(_) => Redirect::to("/").into_response(),
        None => next.run(request).await,
    }
}

////////////////////////////////////////////////////////////////////////
////////////////////////// Extractors //////////////////////////////////
#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let user = parts
            .extensions
            .get::<Session>()
            .unwrap()
            .get::<AuthUser>(USER_SESSION_KEY)
            .await
            .unwrap();

        match user {
            Some(user) => Ok(AuthUser { name: user.name }),
            None => Err(Redirect::to("/signin")),
        }
    }
}
