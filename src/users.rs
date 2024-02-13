use oauth2::CsrfToken;
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub name: String,
    pub email: String,
    pub password: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub active: bool,

    #[serde(with = "time::serde::iso8601")]
    pub created_at: OffsetDateTime,

    #[serde(with = "time::serde::iso8601::option")]
    pub updated_at: Option<OffsetDateTime>,

    #[serde(with = "time::serde::iso8601::option")]
    pub last_login: Option<OffsetDateTime>,
}

// access token.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password", &self.password)
            .field("email", &self.email)
            .field("name", &self.name)
            .field("active", &self.active)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_login", &self.last_login)
            .field("access_token", &"[redacted]")
            .field("refresh_token", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub enum Credentials {
    Password(PasswordCreds),
    OAuth(OAuthCreds),
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordCreds {
    pub username: String,
    pub password: String,
    pub next: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthCreds {
    pub code: String,
    pub old_state: CsrfToken,
    pub new_state: CsrfToken,
}

impl User {}
