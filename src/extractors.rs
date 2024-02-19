use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::Redirect,
};
use tower_sessions::Session;

use crate::{users::AuthUser, web::auth::USER_SESSION_KEY};

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
            None => Err(Redirect::to("/login")),
        }
    }
}
