use axum::{
    http::header::{AUTHORIZATION, USER_AGENT},
    Error,
};
use oauth2::{
    basic::{BasicClient, BasicRequestTokenError},
    reqwest::{async_http_client, AsyncHttpClientError},
    AuthorizationCode, CsrfToken, Scope, TokenResponse,
};
use password_auth::verify_password;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sqlx::{query_as, FromRow, PgPool};
use time::OffsetDateTime;
use tokio::task;
use tower_sessions::Session;
use uuid::Uuid;

use crate::web::oauth::CSRF_STATE_KEY;

#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub username: String,
    pub email: String,

    #[serde(skip_serializing)]
    pub password: Option<String>,
    #[serde(skip_serializing)]
    pub access_token: Option<String>,

    #[serde(skip_serializing)]
    pub refresh_token: Option<String>,

    #[serde(with = "time::serde::iso8601")]
    pub created_at: OffsetDateTime,

    #[serde(with = "time::serde::iso8601::option")]
    pub updated_at: Option<OffsetDateTime>,

    #[serde(with = "time::serde::iso8601::option")]
    pub deleted_at: Option<OffsetDateTime>,

    #[serde(with = "time::serde::iso8601::option")]
    pub last_login: Option<OffsetDateTime>,
}

// access token.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("updated_at", &self.deleted_at)
            .field("last_login", &self.last_login)
            .field("password", &"[redacted]")
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

#[derive(Debug, Deserialize)]
struct UserInfo {
    name: String,
    email: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error(transparent)]
    Sqlx(sqlx::Error),

    #[error(transparent)]
    Reqwest(reqwest::Error),

    #[error(transparent)]
    OAuth2(BasicRequestTokenError<AsyncHttpClientError>),

    #[error(transparent)]
    TaskJoin(#[from] task::JoinError),
}

impl User {
    pub async fn authenticate(
        creds: Credentials,
        db: PgPool,
        client: BasicClient,
    ) -> Result<Option<User>, AuthError> {
        match creds {
            Credentials::Password(password_cred) => {
                let user: Option<Self> =
                    query_as("select * from users where username = $1 and password is not null")
                        .bind(password_cred.username)
                        .fetch_optional(&db)
                        .await
                        .map_err(AuthError::Sqlx)?;

                // Verifying the password is blocking and potentially slow, so we'll do so via
                // `spawn_blocking`.
                task::spawn_blocking(|| {
                    // We're using password-based authentication: this works by comparing our form
                    // input with an argon2 password hash.
                    Ok(user.filter(|user| {
                        let Some(ref password) = user.password else {
                            return false;
                        };
                        verify_password(password_cred.password, password).is_ok()
                    }))
                })
                .await?
            }

            Credentials::OAuth(oauth_creds) => {
                // Ensure the CSRF state has not been tampered with.
                if oauth_creds.old_state.secret() != oauth_creds.new_state.secret() {
                    return Ok(None);
                };

                // Process authorization code, expecting a token response back.
                let token_res = client
                    .exchange_code(AuthorizationCode::new(oauth_creds.code))
                    .request_async(async_http_client)
                    .await
                    .map_err(AuthError::OAuth2)?;

                // Use access token to request user info.
                let user_info = reqwest::Client::new()
                    .get("https://www.googleapis.com/oauth2/v3/userinfo")
                    .header(USER_AGENT.as_str(), "login")
                    .header(
                        AUTHORIZATION.as_str(),
                        format!("Bearer {}", token_res.access_token().secret()),
                    )
                    .send()
                    .await
                    .map_err(AuthError::Reqwest)?
                    .json::<UserInfo>()
                    .await
                    .map_err(AuthError::Reqwest)?;

                // Persist user in our database so we can use `get_user`.
                let user = query_as(
                    r#"
                    insert into users (name, username, email, access_token)
                    values ($1, $2, $2, $3)
                    on conflict(username) do update
                    set access_token = excluded.access_token
                    returning *
                    "#,
                )
                .bind(user_info.name)
                .bind(user_info.email)
                .bind(token_res.access_token().secret())
                .fetch_one(&db)
                .await
                .map_err(AuthError::Sqlx)?;

                Ok(Some(user))
            }
        }
    }
}

pub struct GoogleOauth;

impl GoogleOauth {
    pub async fn authorize_url(client: BasicClient, session: Session) -> String {
        let scopes = vec![
            Scope::new("https://www.googleapis.com/auth/userinfo.email".to_string()),
            Scope::new("https://www.googleapis.com/auth/userinfo.profile".to_string()),
        ];

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes.iter().cloned())
            .url();

        session
            .insert(CSRF_STATE_KEY, csrf_token)
            .await
            .expect("session failed to insert oauth csrf token");

        auth_url.to_string()
    }
}
