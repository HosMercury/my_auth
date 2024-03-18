use crate::{validations, web::keygen::os_keygen};
use axum::http::header::{AUTHORIZATION, USER_AGENT};
use oauth2::{
    basic::{BasicClient, BasicRequestTokenError},
    reqwest::{async_http_client, AsyncHttpClientError},
    AuthorizationCode, CsrfToken, Scope, TokenResponse,
};
use password_auth::{generate_hash, verify_password};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_trim::*;
use sqlx::{query, query_as, FromRow, PgPool};
use std::fmt::Debug;
use time::OffsetDateTime;
use tokio::task;
use uuid::Uuid;
use validations::{validate_password, REGEX_NAME, REGEX_USERNAME};
use validator::Validate;

#[derive(Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub provider: String,

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
    pub last_sign: Option<OffsetDateTime>,
}

// access token.
impl Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("provider", &self.provider)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("updated_at", &self.deleted_at)
            .field("last_sign", &self.last_sign)
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PasswordCreds {
    #[serde(deserialize_with = "string_trim")]
    pub username: String,

    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthCreds {
    pub code: String,
    pub old_state: CsrfToken,
    pub new_state: CsrfToken,
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    given_name: String,
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RegisterUser {
    WebUser(SignUp),
    ApiUser(ApiUser),
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate, Default)]
pub struct SignUp {
    #[validate(
        regex(code = "regex_name", path = "REGEX_NAME",),
        length(code = "min_length", min = 8),
        length(code = "max_length", max = 50)
    )]
    #[serde(deserialize_with = "string_trim")]
    pub name: String,

    #[validate(
        regex(code = "regex_username", path = "REGEX_USERNAME",),
        length(code = "min_length", min = 8),
        length(code = "max_length", max = 50)
    )]
    #[serde(deserialize_with = "string_trim")]
    pub username: String,

    #[validate(
        custom(code = "invalid_password", function = "validate_password",),
        length(code = "min_length", min = 8,),
        length(code = "max_length", max = 500,)
    )]
    pub password: String,

    #[validate(must_match(code = "must_match", other = "password"))]
    pub password2: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ApiUser {
    #[validate(
        regex(code = "regex_name", path = "REGEX_NAME",),
        length(code = "min_length", min = 8),
        length(code = "max_length", max = 50)
    )]
    #[serde(deserialize_with = "string_trim")]
    pub name: String,

    #[validate(email(code = "email"))]
    #[serde(deserialize_with = "string_trim")]
    pub email: String,
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
            Credentials::Password(PasswordCreds { username, password }) => {
                let user = query_as!(
                    Self,
                    r#"SELECT * FROM users WHERE username = $1 
                    AND password IS NOT NULL 
                    AND deleted_at IS NULL"#,
                    username,
                )
                .fetch_optional(&db)
                .await
                .map_err(AuthError::Sqlx)?;

                // Verifying the password is blocking and potentially slow, so we'll do so via
                let user_result = task::spawn_blocking(|| {
                    // We're using password-based authentication: this works by comparing our form
                    // input with an argon2 password hash.
                    Ok(user.filter(|user| {
                        let Some(ref db_password) = user.password else {
                            return false;
                        };
                        verify_password(password, db_password).is_ok()
                    }))
                })
                .await
                .map_err(AuthError::TaskJoin)?;

                match user_result {
                    Ok(user) => match user {
                        Some(user) => Ok(Some(user)),
                        None => Ok(None),
                    },
                    Err(err) => Err(err),
                }
            }

            Credentials::OAuth(OAuthCreds {
                code,
                old_state,
                new_state,
            }) => {
                // Ensure the CSRF state has not been tampered with.
                if old_state.secret() != new_state.secret() {
                    return Ok(None);
                };

                // Process authorization code, expecting a token response back.
                let token_response = client
                    .exchange_code(AuthorizationCode::new(code))
                    .request_async(async_http_client)
                    .await
                    .map_err(AuthError::OAuth2)?;

                // Use access token to request user info.
                let user_info = reqwest::Client::new()
                    .get("https://www.googleapis.com/oauth2/v3/userinfo")
                    .header(USER_AGENT.as_str(), "signin")
                    .header(
                        AUTHORIZATION.as_str(),
                        format!("Bearer {}", token_response.access_token().secret()),
                    )
                    .send()
                    .await
                    .map_err(AuthError::Reqwest)?
                    .json::<UserInfo>()
                    .await
                    .map_err(AuthError::Reqwest)?;

                // Persist user in our database so we can use `get_user`.
                let user = query_as!(
                    User,
                    r#"
                        INSERT INTO users (name, email, access_token, provider)
                        VALUES ($1, $2, $3, $4)
                        ON CONFLICT(email) DO UPDATE
                        SET access_token = excluded.access_token
                        RETURNING *
                    "#,
                    user_info.given_name,
                    user_info.email,
                    token_response.access_token().secret(),
                    "google"
                )
                .fetch_one(&db)
                .await
                .map_err(AuthError::Sqlx)?;

                Ok(Some(user))
            }
        }
    }

    pub async fn register(payload: RegisterUser, db: PgPool) -> Result<User, AuthError> {
        match payload {
            RegisterUser::WebUser(SignUp {
                name,
                username,
                password,
                ..
            }) => {
                let hashed_password = task::spawn_blocking(|| generate_hash(password))
                    .await
                    .expect("Hashing password failed");

                let user = query_as!(
                    Self,
                    r#"
                    INSERT INTO users (name, username, password)
                    VALUES ($1, $2, $3)
                    RETURNING *
                "#,
                    name,
                    username,
                    hashed_password
                )
                .fetch_one(&db)
                .await
                .map_err(AuthError::Sqlx)?;

                Ok(user)
            }
            RegisterUser::ApiUser(ApiUser { name, email }) => {
                let api_key = os_keygen();
                let user = query_as!(
                    Self,
                    r#"
                    INSERT INTO users (name, email, provider, access_token)
                    VALUES ($1, $2, $3, $4)
                    RETURNING *
                "#,
                    name,
                    email,
                    "api",
                    api_key
                )
                .fetch_one(&db)
                .await
                .map_err(AuthError::Sqlx)?;

                Ok(user)
            }
        }
    }

    pub async fn deactivate(&self, db: PgPool) -> Result<Option<User>, AuthError> {
        let result = query_as!(
            User,
            r#"UPDATE users SET deleted_at = $1 WHERE id = $2 RETURNING *"#,
            OffsetDateTime::now_utc(),
            self.id
        )
        .fetch_optional(&db)
        .await
        .map_err(AuthError::Sqlx)?;

        match result {
            Some(user) => Ok(Some(user)),
            None => Ok(None),
        }
    }
}

pub struct GoogleOauth;

impl GoogleOauth {
    pub fn authorize_url(client: BasicClient) -> (Url, CsrfToken) {
        let scopes = vec![
            Scope::new("https://www.googleapis.com/auth/userinfo.email".to_string()),
            Scope::new("https://www.googleapis.com/auth/userinfo.profile".to_string()),
        ];

        client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes.iter().cloned())
            .url()
    }
}
