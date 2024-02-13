use password_auth::verify_password;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Pool, Postgres};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;
use validation::{validate_password, RE_USERNAME};
use validator::Validate;

use crate::validation;

#[derive(Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    name: String,
    pub username: String,
    pub email: Option<String>,
    password: String,
    active: bool,

    #[serde(with = "time::serde::iso8601")]
    pub created_at: OffsetDateTime,

    #[serde(with = "time::serde::iso8601::option")]
    pub updated_at: Option<OffsetDateTime>,

    #[serde(with = "time::serde::iso8601::option")]
    pub last_login: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Validate, Deserialize)]
pub struct Credentials {
    #[validate(
        length(min = 4, message = "Username must be greater than 4 chars"),
        regex(
            path = "RE_USERNAME",
            message = "Username must be alphanumeric and/or dashes only"
        )
    )]
    pub username: String,

    #[validate(
        length(min = 4, message = "Password must be more than 4 letters"),
        custom(
            function = "validate_password",
            message = "password must be 4-50 characters long, contain letters and numbers, and must not contain spaces, special characters, or emoji"
        )
    )]
    pub password: String,
}

#[derive(Debug, Clone, Validate, Deserialize)]
pub struct SignUpPayload {
    #[validate(
        length(min = 4, message = "Username must be more than 4 letters"),
        regex(
            path = "RE_USERNAME",
            message = "Username must be alphanumeric and/or dashes only"
        )
    )]
    username: String,

    #[validate(email)]
    email: Option<String>,

    #[validate(
        length(min = 4, message = "Password must be more than 4 letters"),
        custom(
            function = "validate_password",
            message = "password must be 4-50 characters long, contain letters and numbers, and must not contain spaces, special characters, or emoji"
        )
    )]
    password: String,
}

#[derive(Debug, Clone, Validate, Deserialize)]
pub struct UserUppdate {
    name: Option<String>,
    email: Option<String>,
}

#[derive(Error, Debug)]
pub enum UserError {
    #[error("Credentials do not match our records")]
    BadCredientials(String),

    #[error("Error while saving user")]
    Registeration(String),

    #[error("Error while getting user")]
    Fetching(String),

    #[error("Error while activating user")]
    Activation(String),

    #[error("Error while deactivating user")]
    DeActivation(String),

    #[error("Error while checking user activity")]
    ActivationCheck(String),

    #[error("Error while updating user data")]
    UpdateingUser(String),

    #[error("Error while updating user email")]
    UpdateingEmail(String),

    #[error("Error while updating user name")]
    UpdateingName(String),

    #[error("Error while updating user password")]
    UpdateingPassword(String),
}

impl User {
    async fn sign_in(&self, creds: Credentials, db: &Pool<Postgres>) -> Result<User, UserError> {
        let result = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE username = $1 LIMIT 1",
            creds.username
        )
        .fetch_one(db)
        .await;

        match result {
            Ok(user) => match verify_password(creds.password, &user.password) {
                Ok(_) => Ok(user),
                Err(err) => Err(UserError::BadCredientials(err.to_string())),
            },
            Err(err) => Err(UserError::BadCredientials(err.to_string())),
        }
    }

    async fn sign_up(
        &self,
        payload: SignUpPayload,
        db: &Pool<Postgres>,
    ) -> Result<bool, UserError> {
        let result = sqlx::query!(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
            payload.username,
            payload.email,
            payload.password
        )
        .execute(db)
        .await;

        match result {
            Ok(_) => Ok(true),
            Err(err) => Err(UserError::Registeration(err.to_string())),
        }
    }

    async fn get(&self, id: Uuid, db: &Pool<Postgres>) -> Result<User, UserError> {
        let result = sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", id)
            .fetch_one(db)
            .await;

        match result {
            Ok(user) => Ok(user),
            Err(err) => Err(UserError::Fetching(err.to_string())),
        }
    }

    async fn update_name(
        &self,
        id: Uuid,
        new_name: String,
        db: &Pool<Postgres>,
    ) -> Result<bool, UserError> {
        let result = sqlx::query!("UPDATE users SET name = $1 WHERE id = $2", new_name, id)
            .execute(db)
            .await;

        match result {
            Ok(_) => Ok(true),
            Err(err) => Err(UserError::UpdateingName(err.to_string())),
        }
    }

    async fn update_email(
        &self,
        id: Uuid,
        new_email: String,
        db: &Pool<Postgres>,
    ) -> Result<bool, UserError> {
        let result = sqlx::query!("UPDATE users SET email = $1 WHERE id = $2", new_email, id)
            .execute(db)
            .await;

        match result {
            Ok(_) => Ok(true),
            Err(err) => Err(UserError::UpdateingEmail(err.to_string())),
        }
    }

    async fn update_username(
        &self,
        id: Uuid,
        new_username: String,
        db: &Pool<Postgres>,
    ) -> Result<bool, UserError> {
        let result = sqlx::query!(
            "UPDATE users SET username = $1 WHERE id = $2",
            new_username,
            id
        )
        .execute(db)
        .await;

        match result {
            Ok(_) => Ok(true),
            Err(err) => Err(UserError::UpdateingEmail(err.to_string())),
        }
    }

    /// update user => name and/or email /////
    async fn update_user(
        &self,
        id: Uuid,
        payload: UserUppdate,
        db: &Pool<Postgres>,
    ) -> Result<bool, UserError> {
        let result = sqlx::query!(
            "UPDATE users SET email = $2 ,name = $3 , updated_at = $4 WHERE id = $1",
            id,
            payload.email,
            payload.name,
            OffsetDateTime::now_utc()
        )
        .execute(db)
        .await;

        match result {
            Ok(_) => Ok(true),
            Err(err) => Err(UserError::UpdateingUser(err.to_string())),
        }
    }

    async fn update_password(
        &self,
        id: Uuid,
        new_password: String,
        db: &Pool<Postgres>,
    ) -> Result<bool, UserError> {
        let result = sqlx::query!(
            "UPDATE users SET password = $2, updated_at = $3 WHERE id = $1",
            id,
            new_password,
            OffsetDateTime::now_utc()
        )
        .execute(db)
        .await;

        match result {
            Ok(_) => Ok(true),
            Err(err) => Err(UserError::UpdateingPassword(err.to_string())),
        }
    }

    async fn de_activate(&self, id: Uuid, db: &Pool<Postgres>) -> Result<(), UserError> {
        let result = sqlx::query!(
            "UPDATE users SET active = false , updated_at =$2 WHERE id = $1",
            id,
            OffsetDateTime::now_utc()
        )
        .execute(db)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(err) => Err(UserError::DeActivation(err.to_string())),
        }
    }

    async fn activate(&self, id: Uuid, db: &Pool<Postgres>) -> Result<(), UserError> {
        let result = sqlx::query!(
            "UPDATE users SET active = true , updated_at =$2 WHERE id = $1",
            id,
            OffsetDateTime::now_utc()
        )
        .execute(db)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(err) => Err(UserError::Activation(err.to_string())),
        }
    }

    async fn is_active(&self, id: Uuid, db: &Pool<Postgres>) -> Result<bool, UserError> {
        let result = self.get(id, db).await;
        match result {
            Ok(user) => Ok(user.active),
            Err(err) => Err(UserError::ActivationCheck(err.to_string())),
        }
    }
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}
