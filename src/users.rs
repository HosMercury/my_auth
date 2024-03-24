use crate::{validations, web::keygen::os_keygen};
use anyhow::Result;
use axum::http::header::{AUTHORIZATION, USER_AGENT};
use oauth2::TokenResponse;
use oauth2::{basic::BasicClient, reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope};
use password_auth::{generate_hash, verify_password};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_trim::*;
use sqlx::{query_as, FromRow, PgPool};
use std::fmt::Debug;
use time::OffsetDateTime;
use tokio::task;
use uuid::Uuid;
use validations::{validate_password, REGEX_NAME, REGEX_USERNAME};
use validator::Validate;

#[derive(Serialize, Deserialize, Clone, FromRow)]
pub struct User {
    pub uid: Uuid,
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
            .field("uid", &self.uid)
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

#[derive(Serialize, Deserialize)]
pub struct UserWithRoles {
    pub user: User,
    pub roles: Vec<Role>,
}

impl User {
    pub async fn authenticate(
        creds: Credentials,
        db: &PgPool,
        client: BasicClient,
    ) -> Result<Option<User>> {
        match creds {
            Credentials::Password(PasswordCreds { username, password }) => {
                let user = query_as!(
                    Self,
                    r#"SELECT * FROM users WHERE username = $1 
                    AND password IS NOT NULL 
                    AND deleted_at IS NULL"#,
                    username,
                )
                .fetch_optional(db)
                .await?;

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
                    query_as!(
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
                    .fetch_one(db)
                    .await?,
                ))
            }
        }
    }

    pub async fn register(payload: RegisterUser, db: &PgPool) -> Result<User> {
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

                Ok(query_as!(
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
                .fetch_one(db)
                .await?)
            }
            RegisterUser::ApiUser(ApiUser { name, email }) => Ok(query_as!(
                Self,
                r#"
                    INSERT INTO users (name, email, provider, access_token)
                    VALUES ($1, $2, $3, $4)
                    RETURNING *
                "#,
                name,
                email,
                "api",
                os_keygen()
            )
            .fetch_one(db)
            .await?),
        }
    }

    pub async fn all(db: &PgPool) -> Result<Vec<User>> {
        Ok(query_as!(User, "SELECT * FROM users").fetch_all(db).await?)
    }

    pub async fn find(uid: Uuid, db: &PgPool) -> Result<User> {
        Ok(
            query_as!(User, r#"SELECT * FROM users WHERE uid = $1"#, uid)
                .fetch_one(db)
                .await?,
        )
    }

    pub async fn with_roles(&self, db: &PgPool) -> Result<UserWithRoles> {
        Ok(UserWithRoles {
            user: self.clone(),
            roles: self.roles(db).await?,
        })
    }

    pub async fn deactivate(&self, db: &PgPool) -> Result<User> {
        Ok(query_as!(
            User,
            r#"UPDATE users SET deleted_at = $1 WHERE uid = $2 RETURNING *"#,
            OffsetDateTime::now_utc(),
            self.uid
        )
        .fetch_one(db)
        .await?)
    }

    pub async fn roles(&self, db: &PgPool) -> Result<Vec<Role>> {
        // if no permissions - it will return empty vec
        Ok(query_as!(
            Role,
            r#"
        SELECT r.* FROM roles r

        JOIN users_roles ur ON r.uid = ur.role_uid
        JOIN users u ON ur.user_uid = u.uid

        WHERE u.uid = $1
        "#,
            self.uid
        )
        .fetch_all(db)
        .await?)
    }

    pub async fn permissions(&self, db: &PgPool) -> Result<Vec<Permission>> {
        // if no permissions - it will return empty vec
        Ok(query_as!(
            Permission,
            r#"
        SELECT p.* FROM permissions p

        JOIN roles_permissions rp ON p.uid = rp.permission_uid
        JOIN roles r ON rp.role_uid = r.uid
        JOIN users_roles ur ON r.uid = ur.role_uid
        JOIN users u ON ur.user_uid = u.uid

        WHERE u.uid = $1
        "#,
            self.uid
        )
        .fetch_all(db)
        .await?)
    }

    pub async fn has_role(&self, role_uid: Uuid, db: &PgPool) -> Result<bool> {
        Ok(self.roles(db).await?.into_iter().any(|r| r.uid == role_uid))
    }

    pub async fn has_permission(&self, permission_uid: Uuid, db: &PgPool) -> Result<bool> {
        Ok(self
            .permissions(db)
            .await?
            .into_iter()
            .any(|p| p.uid == permission_uid))
    }
}

#[derive(Serialize, Deserialize, FromRow, sqlx::Type)]
pub struct Role {
    pub uid: Uuid,
    pub name: String,
}

// impl sqlx::Type<sqlx::Postgres> for Role {
//     fn type_info() -> sqlx::postgres::PgTypeInfo {
//         sqlx::postgres::PgTypeInfo::with_name("_roles")
//     }
// }

impl Role {
    pub async fn new(name: String, db: &PgPool) -> Result<Role> {
        Ok(query_as!(
            Role,
            "INSERT INTO roles (name) VALUES ($1) RETURNING *",
            name
        )
        .fetch_one(db)
        .await?)
    }

    pub async fn all(db: &PgPool) -> Result<Vec<Role>> {
        Ok(query_as!(Role, "SELECT * FROM roles").fetch_all(db).await?)
    }

    pub async fn find(uid: Uuid, db: &PgPool) -> Result<Role> {
        Ok(query_as!(Role, "SELECT * FROM roles WHERE uid = $1", uid)
            .fetch_one(db)
            .await?)
    }

    pub async fn update(&self, name: String, db: &PgPool) -> Result<Role> {
        Ok(query_as!(
            Role,
            "UPDATE roles SET name = $2 WHERE uid = $1 RETURNING *",
            self.uid,
            name
        )
        .fetch_one(db)
        .await?)
    }

    pub async fn permissions(&self, db: &PgPool) -> Result<Vec<Permission>> {
        Ok(query_as!(
            Permission,
            r#"
            SELECT p.* FROM permissions p

            JOIN roles_permissions rp ON rp.permission_uid = p.uid 
            JOIN roles r ON rp.role_uid = r.uid 

            WHERE r.uid = $1
        "#,
            self.uid
        )
        .fetch_all(db)
        .await?)
    }

    pub async fn has_permission(&self, permission_uid: Uuid, db: &PgPool) -> Result<bool> {
        Ok(self
            .permissions(db)
            .await?
            .into_iter()
            .any(|p| p.uid == permission_uid))
    }
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct Permission {
    pub uid: Uuid,
    pub name: String,
}

impl Permission {
    pub async fn new(name: String, db: &PgPool) -> Result<Permission> {
        Ok(query_as!(
            Permission,
            "INSERT INTO permissions (name) VALUES ($1) RETURNING *",
            name
        )
        .fetch_one(db)
        .await?)
    }

    pub async fn find(uid: Uuid, db: &PgPool) -> Result<Permission> {
        Ok(
            query_as!(Permission, "SELECT * FROM permissions WHERE uid = $1", uid)
                .fetch_one(db)
                .await?,
        )
    }

    pub async fn all(db: &PgPool) -> Result<Vec<Permission>> {
        Ok(query_as!(Permission, "SELECT * FROM permissions")
            .fetch_all(db)
            .await?)
    }

    pub async fn update(&self, name: String, db: &PgPool) -> Result<Permission> {
        Ok(query_as!(
            Permission,
            "UPDATE permissions SET name = $2 WHERE uid = $1 RETURNING *",
            self.uid,
            name
        )
        .fetch_one(db)
        .await?)
    }

    pub async fn roles(&self, db: &PgPool) -> Result<Vec<Role>> {
        Ok(query_as!(
            Role,
            r#"
            SELECT r.* FROM roles r
            JOIN roles_permissions rp ON rp.role_uid = r.uid 
            JOIN permissions p ON rp.permission_uid = p.uid 
            WHERE p.uid = $1
        "#,
            self.uid
        )
        .fetch_all(db)
        .await?)
    }

    pub async fn has_role(&self, role_uid: Uuid, db: &PgPool) -> Result<bool> {
        Ok(self.roles(db).await?.into_iter().any(|r| r.uid == role_uid))
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

// impl FromRow<'_, PgRow> for UserWithRoles {
//     fn from_row(row: &PgRow) -> sqlx::Result<Self> {
//         let user = User {
//             uid: row.get("uid"),
//             name: row.get("name"),
//             username: row.get("username"),
//             email: row.get("email"),
//             provider: row.get("provider"),
//             created_at: row.get("created_at"),
//             updated_at: row.get("updated_at"),
//             deleted_at: row.get("deleted_at"),
//             last_sign: row.get("last_sign"),
//             password: None,
//             access_token: None,
//             refresh_token: None,
//         };

//         let roles = row.get("roles!: Vec<Role>");

//         Ok(Self { user, roles })
//     }
// }

// impl PgHasArrayType for Role {
//     fn array_type_info() -> PgTypeInfo {
//         PgTypeInfo::with_name("roles!: Vec<Role>")
//     }
// }
