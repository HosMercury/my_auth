use crate::{validations, web::{auth::USER_SESSION_KEY, oauth::CSRF_STATE_KEY}};
use axum::http::header::{AUTHORIZATION, USER_AGENT};
use lazy_static::lazy_static;
use oauth2::{
    basic::{BasicClient, BasicRequestTokenError},
    reqwest::{async_http_client, AsyncHttpClientError},
    AuthorizationCode, CsrfToken, Scope, TokenResponse,
};
use password_auth::verify_password;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::{query_as, FromRow, PgPool};
use time::OffsetDateTime;
use tokio::task;
use tower_sessions::Session;
use uuid::Uuid;
use validations::validate_password;
use validator::Validate;

lazy_static! {
    pub static ref REGEX_NAME: Regex = Regex::new(r"^[a-zA-Z]{3,}[a-zA-Z0-9 ]{3,50}$").unwrap();
    pub static ref REGEX_USERNAME: Regex = Regex::new(r"^[a-zA-Z0-9_-]{8,50}$").unwrap();
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: Uuid,
    pub name: String,
}

impl AuthUser {
    #[allow(unused)]
    pub async fn is_authenticated(&self, session: Session) -> bool {
        session
            .get::<AuthUser>(USER_SESSION_KEY)
            .await
            .unwrap()
            .is_some()
    }
}

#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub locale: String,

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
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("locale", &self.locale)
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

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordCreds {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthCreds {
    pub code: String,
    pub old_state: CsrfToken,
    pub new_state: CsrfToken,
}

#[derive(Debug, Clone, Deserialize, Validate)]
pub struct SignUp {
    #[validate(
        regex(
            path = "REGEX_NAME",
            message = "Name must be alphabetic and could contain space only"
        ),
        length(min = 6, message = "Name must be at least 6 chars"),
        length(max = 50, message = "Name must not exceed 50 chars")
    )]
    pub name: String,

    #[validate(
        regex(
            path = "REGEX_USERNAME",
            message = "Username must be alphanumeric and/or dashes 0r underscore only"
        ),
        length(min = 8, message = "Username must be  at least 8 chars"),
        length(max = 50, message = "Username must not exceed 50 chars")
    )]
    pub username: String,

    #[validate(
        custom(
            function = "validate_password",
            message = "Username must be at least than 8 characters and must contain only letters, digits, dash and/or underscore"
        ),
        length(min = 8, message = "Password must be at least 8 characters"),
        length(max = 500, message = "Password must not exceed 500 chars")
    )]
    pub password: String,

    #[validate(must_match(other = "password", message = "Passwords are not identical"))]
    pub password2: String,
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    given_name: String,
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
        session: Session,
    ) -> Result<Option<User>, AuthError> {
        match creds {
            Credentials::Password(password_cred) => {
                let user: Option<Self> =
                    query_as("SELECT * FROM users WHERE username = $1 AND password IS NOT NULL")
                        .bind(password_cred.username)
                        .fetch_optional(&db)
                        .await
                        .map_err(AuthError::Sqlx)?;

                // Verifying the password is blocking and potentially slow, so we'll do so via
                let user_result = task::spawn_blocking(|| {
                    // We're using password-based authentication: this works by comparing our form
                    // input with an argon2 password hash.
                    Ok(user.filter(|user| {
                        let Some(ref password) = user.password else {
                            return false;
                        };
                        verify_password(password_cred.password, password).is_ok()
                    }))
                })
                .await
                .map_err(AuthError::TaskJoin)?;

                match user_result {
                    Ok(user) => match user {
                        Some(user) => {
                            session
                                .insert(
                                    USER_SESSION_KEY,
                                    AuthUser {
                                        id: user.id.clone(),
                                        name: user.name.clone(),
                                    },
                                )
                                .await
                                .unwrap();

                            Ok(Some(user))
                        }
                        None => Ok(None),
                    },
                    Err(err) => Err(err),
                }
            }

            Credentials::OAuth(oauth_creds) => {
                // Ensure the CSRF state has not been tampered with.
                if oauth_creds.old_state.secret() != oauth_creds.new_state.secret() {
                    return Ok(None);
                };

                // Process authorization code, expecting a token response back.
                let token_response = client
                    .exchange_code(AuthorizationCode::new(oauth_creds.code))
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
                let user: User = query_as(
                    r#"
                        INSERT INTO users (name, email, access_token)
                        VALUES ($1, $2, $3)
                        ON CONFLICT(email) DO UPDATE
                        SET access_token = excluded.access_token
                        RETURNING *
                    "#,
                )
                .bind(user_info.given_name)
                .bind(user_info.email)
                .bind(token_response.access_token().secret())
                .fetch_one(&db)
                .await
                .map_err(AuthError::Sqlx)?;

                session
                    .insert(
                        USER_SESSION_KEY,
                        AuthUser {
                            id: user.id.clone(),
                            name: user.name.clone(),
                        },
                    )
                    .await
                    .unwrap();

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
            .expect("Session failed to insert oauth csrf token");

        auth_url.to_string()
    }
}
