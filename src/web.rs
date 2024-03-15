pub mod auth;
pub mod main;
pub mod oauth;

use base64::prelude::*;
use oauth2::CsrfToken;
use rand::thread_rng;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use uuid::Uuid;

use crate::users::User;

pub async fn key_gen() -> String {
    let mut key = [0u8; 64];
    thread_rng().fill_bytes(&mut key);
    BASE64_URL_SAFE_NO_PAD.encode(&key)
}

// OS is secure
pub async fn os_key_gen() -> String {
    let mut key = [0u8; 64];
    OsRng.fill_bytes(&mut key);
    BASE64_URL_SAFE_NO_PAD.encode(&key)
}

///////////////////////// Session ///////////////////////
pub const USER_SESSION_KEY: &str = "user";
pub const CSRF_STATE_KEY: &str = "oauth.csrf-state";

#[derive(Serialize, Deserialize)]
pub struct AuthUser {
    pub id: Uuid,
    pub name: String,
}

impl AuthUser {
    #[allow(unused)]
    pub async fn is_authenticated(&self, session: Session) -> bool {
        session
            .get::<Self>(USER_SESSION_KEY)
            .await
            .unwrap()
            .is_some()
    }
}

pub async fn save_session_user(user: User, session: &Session) {
    session
        .insert(
            USER_SESSION_KEY,
            AuthUser {
                id: user.id,
                name: user.name,
            },
        )
        .await
        .expect("Saving user in session failed");
}

// Saving oauth csrf
pub async fn save_session_csrf(csrf_token: CsrfToken, session: Session) {
    session
        .insert(CSRF_STATE_KEY, csrf_token)
        .await
        .expect("Session failed to insert oauth csrf token");
}
