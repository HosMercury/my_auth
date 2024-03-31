use crate::{validations, web::keygen::os_keygen};
use anyhow::Result;
use axum::http::header::{AUTHORIZATION, USER_AGENT};
use chrono::{DateTime, Local};
use oauth2::TokenResponse;
use oauth2::{basic::BasicClient, reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope};
use password_auth::{generate_hash, verify_password};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_trim::*;
use sqlx::{query_as, FromRow, PgPool};
use std::fmt::Debug;
use tokio::task;
use validations::{validate_password, NAME_REGEX, USERNAME_REGEX};
use validator::Validate;

#[derive(Serialize, Deserialize, Clone, Default, FromRow)]
pub struct User {
    pub id: i32,
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
    pub created_at: DateTime<Local>,
    pub updated_at: Option<DateTime<Local>>,
    pub deleted_at: Option<DateTime<Local>>,
    pub last_sign: Option<DateTime<Local>>,
}

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
        regex(code = "NAME_REGEX", path = "NAME_REGEX",),
        length(code = "min_length", min = 8),
        length(code = "max_length", max = 50)
    )]
    #[serde(deserialize_with = "string_trim")]
    pub name: String,

    #[validate(
        regex(code = "USERNAME_REGEX", path = "USERNAME_REGEX",),
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
        regex(code = "NAME_REGEX", path = "NAME_REGEX",),
        length(code = "min_length", min = 8),
        length(code = "max_length", max = 50)
    )]
    #[serde(deserialize_with = "string_trim")]
    pub name: String,

    #[validate(email(code = "email"))]
    #[serde(deserialize_with = "string_trim")]
    pub email: String,
}

impl User {
    pub async fn authenticate(
        creds: Credentials,
        db: &PgPool,
        client: BasicClient,
    ) -> Result<Option<Self>> {
        match creds {
            Credentials::Password(PasswordCreds { username, password }) => {
                let user: Option<User> = query_as(
                    "SELECT * FROM users WHERE username = $1 
                    AND password IS NOT NULL AND deleted_at IS NULL",
                )
                .bind(username)
                .fetch_optional(db)
                .await?;

                // Verifying the password is blocking and potentially slow, so we'll do so via
                let user_result = task::spawn_blocking(|| {
                    Ok(user.filter(|user: &User| {
                        let Some(ref db_password) = user.password else {
                            return false;
                        };
                        verify_password(password, db_password).is_ok()
                    }))
                })
                .await?;

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
                    .await?;

                // Use access token to request user info.
                let user_info = reqwest::Client::new()
                    .get("https://www.googleapis.com/oauth2/v3/userinfo")
                    .header(USER_AGENT.as_str(), "signin")
                    .header(
                        AUTHORIZATION.as_str(),
                        format!("Bearer {}", token_response.access_token().secret()),
                    )
                    .send()
                    .await?
                    .json::<UserInfo>()
                    .await?;

                Ok(Some(
                    query_as(
                        "INSERT INTO users (name, email, access_token, provider)
                        VALUES ($1, $2, $3, $4)
                        ON CONFLICT(email) DO UPDATE
                        SET access_token = excluded.access_token
                        RETURNING *",
                    )
                    .bind(user_info.given_name)
                    .bind(user_info.email)
                    .bind(token_response.access_token().secret())
                    .bind("google")
                    .fetch_one(db)
                    .await?,
                ))
            }
        }
    }

    pub async fn register(payload: RegisterUser, db: &PgPool) -> Result<Self> {
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

                Ok(query_as(
                    "INSERT INTO users (name, username, password)
                    VALUES ($1, $2, $3)
                    RETURNING *",
                )
                .bind(name)
                .bind(username)
                .bind(hashed_password)
                .fetch_one(db)
                .await?)
            }
            RegisterUser::ApiUser(ApiUser { name, email }) => Ok(query_as(
                "INSERT INTO users (name, email, provider, access_token)
                        VALUES ($1, $2, $3, $4)
                        RETURNING *",
            )
            .bind(name)
            .bind(email)
            .bind("api")
            .bind(os_keygen())
            .fetch_one(db)
            .await?),
        }
    }

    pub async fn all(db: &PgPool) -> Result<Vec<Self>> {
        Ok(query_as("SELECT * FROM users").fetch_all(db).await?)
    }

    pub async fn find(id: i32, db: &PgPool) -> Result<User> {
        Ok(query_as("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(db)
            .await?)
    }

    pub async fn deactivate(&self, db: &PgPool) -> Result<Self> {
        Ok(
            query_as("UPDATE users SET deleted_at = $1 WHERE id = $2 RETURNING *")
                .bind(Local::now())
                .bind(self.id)
                .fetch_one(db)
                .await?,
        )
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
