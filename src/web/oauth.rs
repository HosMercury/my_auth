use crate::{
    users::{Credentials, GoogleOauth, OAuthCreds, User},
    AppState,
};
use askama_axum::IntoResponse;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Redirect,
    routing::get,
    Router,
};
use oauth2::CsrfToken;
use serde::Deserialize;
use tower_sessions::Session;

pub const CSRF_STATE_KEY: &str = "oauth.csrf-state";
// pub const NEXT_URL_KEY: &str = "auth.next-url";

#[derive(Debug, Clone, Deserialize)]
pub struct OauthUrlQuery {
    code: String,
    state: CsrfToken,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/google/oauth", get(google_oauth))
        .route("/oauth/callback", get(callback))
}

pub async fn google_oauth(
    State(AppState { client, .. }): State<AppState>,
    session: Session,
) -> impl IntoResponse {
    let url = GoogleOauth::authorize_url(client, session).await;
    Redirect::to(url.as_str())
}

pub async fn callback(
    session: Session,
    State(AppState { client, db }): State<AppState>,
    Query(OauthUrlQuery {
        code,
        state: new_state,
    }): Query<OauthUrlQuery>,
) -> impl IntoResponse {
    let Ok(Some(old_state)) = session.get(CSRF_STATE_KEY).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let creds = Credentials::OAuth(OAuthCreds {
        code,
        old_state,
        new_state,
    });

    match User::authenticate(creds, db, client, session).await {
        Ok(Some(_)) => Redirect::to("/").into_response(),
        Ok(None) => Redirect::to("/login").into_response(),
        Err(_) => Redirect::to("/login").into_response(),
    }
}
