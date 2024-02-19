use askama_axum::IntoResponse;
use axum::{
    extract::Request,
    middleware::Next,
    response::{Redirect, Response},
};
use tower_sessions::Session;

use crate::{users::AuthUser, web::auth::USER_SESSION_KEY};

pub async fn auth_middlware(session: Session, request: Request, next: Next) -> Response {
    let user = session.get::<AuthUser>(USER_SESSION_KEY).await.unwrap();
    if user.is_none() {
        return Redirect::to("/login").into_response();
    }

    let response = next.run(request).await;
    response
}
