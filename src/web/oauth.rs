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

#[derive(Deserialize)]
pub struct OauthUrlQuery {
    code: String,
    state: CsrfToken,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/google/oauth", get(self::get::google_oauth))
        .route("/oauth/callback", get(self::post::callback))
}

mod get {
    use super::*;
    use crate::web::session::save_session_csrf;

    pub async fn google_oauth(
        State(AppState { client, .. }): State<AppState>,
        session: Session,
    ) -> impl IntoResponse {
        let (url, csrf_token) = GoogleOauth::authorize_url(client);
        save_session_csrf(csrf_token, session).await;

        Redirect::to(url.as_str())
    }
}

mod post {
    use super::*;
    use crate::web::session::CSRF_STATE_KEY;

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

        match User::authenticate(creds, db, client).await {
            Ok(Some(_)) => Redirect::to("/").into_response(),
            Ok(None) => Redirect::to("/signin").into_response(),
            Err(_) => Redirect::to("/signin").into_response(),
        }
    }
}
