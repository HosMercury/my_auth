use askama_axum::IntoResponse;
use axum::{
    extract::Request,
    middleware::Next,
    response::{Redirect, Response},
};
use tower_sessions::Session;

use crate::{users::AuthUser, web::auth::USER_SESSION_KEY};

pub async fn auth_middlware(session: Session, request: Request, next: Next) -> Response {
    match session.get::<AuthUser>(USER_SESSION_KEY).await.unwrap() {
        Some(_) => next.run(request).await,
        None => Redirect::to("/login").into_response(),
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
