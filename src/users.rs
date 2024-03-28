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
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::Type;
use sqlx::{query, Row};
use sqlx::{query_as, FromRow, PgPool};
use std::fmt::Debug;
use tokio::task;
use validations::{validate_password, REGEX_NAME, REGEX_USERNAME};
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

static  USER_FIELDS: &str = "id, name, last_login, created_at, username!, email!, updated_at!, deleted_at!, password!, access_token!, refresh_token!";

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

#[derive(Serialize, Deserialize, Debug)]
pub struct UserWithRoles {
    pub user: User,
    pub roles: Option<Vec<Role>>,
}

impl FromRow<'_, PgRow> for UserWithRoles {
    fn from_row(row: &PgRow) -> sqlx::Result<Self> {
        let user: User = User::from_row(row).expect("deser user failed");

        let roles = row
            .try_get::<Json<Vec<Role>>, _>("roles")
            .map(|x| if x.is_empty() { None } else { Some(x.0) })
            .unwrap_or(None);

        println!("{:?}", roles);

        Ok(Self { user, roles })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RoleWithPermissions {
    pub roles: Option<Vec<Permission>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserWithRolesWithPermissions {
    pub user: User,
    pub roles_with_permissions: Option<RoleWithPermissions>,
}

impl User {
    pub async fn authenticate(
        creds: Credentials,
        db: &PgPool,
        client: BasicClient,
    ) -> Result<Option<User>> {
        match creds {
            Credentials::Password(PasswordCreds { username, password }) => {
                let user: Option<User> = query_as(
                    "SELECT * FROM users WHERE username = $1 
                    AND password IS NOT NULL 
                    AND deleted_at IS NULL",
                )
                .bind(username)
                .fetch_optional(db)
                .await?;

                // Verifying the password is blocking and potentially slow, so we'll do so via
                let user_result = task::spawn_blocking(|| {
                    // We're using password-based authentication: this works by comparing our form
                    // input with an argon2 password hash.
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

                let user: User = query_as(
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
                .await?;

                Ok(Some(user))
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

                let user: User = query_as(
                    r#"
                    INSERT INTO users (name, username, password)
                    VALUES ($1, $2, $3)
                    RETURNING *
                "#,
                )
                .bind(name)
                .bind(username)
                .bind(hashed_password)
                .fetch_one(db)
                .await?;

                Ok(user)
            }
            RegisterUser::ApiUser(ApiUser { name, email }) => {
                let user: User = query_as(
                    "INSERT INTO users (name, email, provider, access_token)
                        VALUES ($1, $2, $3, $4)
                        RETURNING *",
                )
                .bind(name)
                .bind(email)
                .bind("api")
                .bind(os_keygen())
                .fetch_one(db)
                .await?;

                Ok(user)
            }
        }
    }

    pub async fn all(db: &PgPool) -> Result<Vec<User>> {
        let users: Vec<User> = query_as("SELECT * FROM users").fetch_all(db).await?;
        Ok(users)
    }

    pub async fn find(id: i32, db: &PgPool) -> Result<User> {
        let user = query_as("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(db)
            .await?;

        Ok(user)
    }

    pub async fn with_roles(id: i32, db: &PgPool) -> Result<UserWithRoles> {
        let user_with_roles: UserWithRoles = sqlx::query_as(
            "SELECT users.*, JSON_AGG(roles.*) As roles FROM users
            LEFT JOIN users_roles ON users_roles.user_id = users.id
            LEFT JOIN roles ON users_roles.role_id = roles.id
            WHERE users.id = $1
            GROUP BY users.id;",
        )
        .bind(id)
        .fetch_one(db)
        .await?;

        Ok(user_with_roles)
    }

    pub async fn with_roles_permissions(id: i32, db: &PgPool) -> Result<()> {
        let sql = "
            SELECT users.*,
            JSON_AGG(user_roles.roles_permissions) as roles
            FROM (
                SELECT
                users.id,
                JSON_BUILD_OBJECT(
                    'role', roles.name,
                    'permissions', JSON_AGG(permissions.*)
                ) as roles_permissions
                    FROM users
                    JOIN users_roles ON users_roles.user_id = users.id
                    JOIN roles ON roles.id = users_roles.role_id
                    JOIN roles_permissions ON roles_permissions.role_id = roles.id
                    JOIN permissions ON permissions.id = roles_permissions.permission_id
                    WHERE users.id = 1
                GROUP BY users.id, roles.id
            ) as user_roles
            JOIN users ON users.id = user_roles.id
            GROUP BY users.id;
            ";

        let row = query(sql).fetch_one(db).await?;

        // let user = User {
        //     id: row.get("id"),
        //     name: row.get("name"),
        //     username: row.get("username"),
        //     email: row.get("email"),
        //     provider: row.get("provider"),
        //     password: None,
        //     access_token: None,
        //     refresh_token: None,
        //     created_at: row.get("created_at"),
        //     updated_at: row.get("updated_at"),
        //     deleted_at: row.get("deleted_at"),
        //     last_sign: row.get("last_sign"),
        // };

        // let roles: UserWithRolesWithPermissions =
        //     serde_json::from_value(row.get("roles")).unwrap_or(None);

        // println!("roles: {:#?}", roles);

        Ok(())
    }

    pub async fn deactivate(&self, db: &PgPool) -> Result<User> {
        let user = query_as("UPDATE users SET deleted_at = $1 WHERE id = $2 RETURNING *")
            .bind(Local::now())
            .bind(self.id)
            .fetch_one(db)
            .await?;
        Ok(user)
    }

    pub async fn roles(&self, db: &PgPool) -> Result<Vec<Role>> {
        // if no permissions - it will return empty vec
        Ok(query_as!(
            Role,
            "SELECT r.* FROM roles r
        JOIN users_roles ur ON r.id = ur.role_id
        JOIN users u ON ur.user_id = u.id
        WHERE u.id = $1",
            self.id
        )
        .fetch_all(db)
        .await?)
    }

    pub async fn permissions(&self, db: &PgPool) -> Result<Vec<Permission>> {
        // if no permissions - it will return empty vec
        Ok(query_as!(
            Permission,
            "SELECT p.* FROM permissions p
        JOIN roles_permissions rp ON p.id = rp.permission_id
        JOIN roles r ON rp.role_id = r.id
        JOIN users_roles ur ON r.id = ur.role_id
        JOIN users u ON ur.user_id = u.id
        WHERE u.id = $1",
            self.id
        )
        .fetch_all(db)
        .await?)
    }
    pub async fn has_role(&self, role_id: i32, db: &PgPool) -> Result<bool> {
        Ok(self.roles(db).await?.into_iter().any(|r| r.id == role_id))
    }

    pub async fn has_permission(&self, permission_id: i32, db: &PgPool) -> Result<bool> {
        Ok(self
            .permissions(db)
            .await?
            .into_iter()
            .any(|p| p.id == permission_id))
    }
}

#[derive(Serialize, Deserialize, FromRow, Type, Debug, Clone)]
pub struct Role {
    pub id: i32,
    pub name: String,
}

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

    pub async fn find(id: i32, db: &PgPool) -> Result<Role> {
        Ok(query_as!(Role, "SELECT * FROM roles WHERE id = $1", id)
            .fetch_one(db)
            .await?)
    }

    pub async fn update(&self, name: String, db: &PgPool) -> Result<Role> {
        Ok(query_as!(
            Role,
            "UPDATE roles SET name = $2 WHERE id = $1 RETURNING *",
            self.id,
            name
        )
        .fetch_one(db)
        .await?)
    }

    pub async fn permissions(&self, db: &PgPool) -> Result<Vec<Permission>> {
        Ok(query_as!(
            Permission,
            "
            SELECT p.* FROM permissions p

            JOIN roles_permissions rp ON rp.permission_id = p.id 
            JOIN roles r ON rp.role_id = r.id 

            WHERE r.id = $1
        ",
            self.id
        )
        .fetch_all(db)
        .await?)
    }

    pub async fn has_permission(&self, permission_id: i32, db: &PgPool) -> Result<bool> {
        Ok(self
            .permissions(db)
            .await?
            .into_iter()
            .any(|p| p.id == permission_id))
    }
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
pub struct Permission {
    pub id: i32,
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

    pub async fn find(id: i32, db: &PgPool) -> Result<Permission> {
        Ok(
            query_as!(Permission, "SELECT * FROM permissions WHERE id = $1", id)
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
            "UPDATE permissions SET name = $2 WHERE id = $1 RETURNING *",
            self.id,
            name
        )
        .fetch_one(db)
        .await?)
    }

    pub async fn roles(&self, db: &PgPool) -> Result<Vec<Role>> {
        Ok(query_as!(
            Role,
            "SELECT r.* FROM roles r
            JOIN roles_permissions rp ON rp.role_id = r.id 
            JOIN permissions p ON rp.permission_id = p.id 
            WHERE p.id = $1",
            self.id
        )
        .fetch_all(db)
        .await?)
    }

    pub async fn has_role(&self, role_id: i32, db: &PgPool) -> Result<bool> {
        Ok(self.roles(db).await?.into_iter().any(|r| r.id == role_id))
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
