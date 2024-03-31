use crate::users::User;
use anyhow::Result;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{query, Row};
use sqlx::{query_as, FromRow, PgPool};
use std::fmt::Debug;

//User authorization impl
impl User {
    pub async fn roles(&self, db: &PgPool) -> Result<Vec<Role>> {
        // if no permissions - it will return empty vec
        Ok(query_as(
            "SELECT r.* FROM roles r
                JOIN users_roles ur ON r.id = ur.role_id
                JOIN users u ON ur.user_id = u.id
                WHERE u.id = $1",
        )
        .bind(self.id)
        .fetch_all(db)
        .await?)
    }

    pub async fn permissions(&self, db: &PgPool) -> Result<Vec<Permission>> {
        // if no permissions - it will return empty vec
        Ok(query_as(
            "SELECT p.* FROM permissions p
                  JOIN roles_permissions rp ON p.id = rp.permission_id
                  JOIN roles r ON rp.role_id = r.id
                  JOIN users_roles ur ON r.id = ur.role_id
                  JOIN users u ON ur.user_id = u.id
                  WHERE u.id = $1",
        )
        .bind(self.id)
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

    // Get the user and their roles and return permissions
    pub async fn with_roles_permissions(id: i32, db: &PgPool) -> Result<()> {
        let row = query(
            "WITH role_perms AS (
                SELECT
                    roles.id AS role_id,
                    jsonb_build_object('role', roles.*, 'permissions', jsonb_agg(permissions.*)) AS role_permissions
                FROM
                    roles
                    LEFT JOIN roles_permissions rp ON rp.role_id = roles.id
                    LEFT JOIN permissions ON rp.permission_id = permissions.id
                GROUP BY
                    roles.id
            ),
            user_roles_permissions AS (
                SELECT
                    users.*,
                    jsonb_build_object('roles', jsonb_agg(role_perms.role_permissions)) AS roles
                FROM
                    users
                    LEFT JOIN users_roles ON users.id = users_roles.user_id
                    LEFT JOIN roles ON users_roles.role_id = roles.id
                    LEFT JOIN role_perms ON roles.id = role_perms.role_id
                WHERE
                    users.id = $1
                GROUP BY
                    users.id
            )
            SELECT
                *
            FROM
                user_roles_permissions;",
        )
        .bind(id)
        .fetch_one(db)
        .await?;

        let user: User = User::from_row(&row).unwrap();

        let roles = row
            .try_get::<Json<Option<Roles>>, _>("roles")
            .map(|x| x.0)
            .unwrap_or(None);

        println!("{:#?}", roles);

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserWithRoles {
    pub user: User,
    pub roles: Vec<Role>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Roles {
    pub roles: Vec<RoleWithPermissions>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RoleWithPermissions {
    pub role: Role,
    pub permissions: Option<Vec<Option<Permission>>>,
}

#[derive(Serialize, Deserialize, FromRow, Debug, Clone, Default)]
pub struct Role {
    pub id: i32,
    pub name: String,
    pub created_at: DateTime<Local>,
    pub updated_at: Option<DateTime<Local>>,
    pub deleted_at: Option<DateTime<Local>>,
}

impl FromRow<'_, PgRow> for UserWithRoles {
    fn from_row(row: &PgRow) -> sqlx::Result<Self> {
        let user: User = User::from_row(row).expect("deser user failed");

        let roles = row
            .try_get::<Json<Vec<Role>>, _>("roles")
            .map(|x| x.0)
            .unwrap_or(vec![]);

        println!("{:?}", roles);

        Ok(Self { user, roles })
    }
}

impl Role {
    pub async fn create(name: String, db: &PgPool) -> Result<Self> {
        Ok(query_as("INSERT INTO roles (name) VALUES ($1) RETURNING *")
            .bind(name)
            .fetch_one(db)
            .await?)
    }

    pub async fn all(db: &PgPool) -> Result<Vec<Self>> {
        Ok(query_as("SELECT * FROM roles").fetch_all(db).await?)
    }

    pub async fn find(id: i32, db: &PgPool) -> Result<Role> {
        Ok(query_as("SELECT * FROM roles WHERE id = $1")
            .bind(id)
            .fetch_one(db)
            .await?)
    }

    pub async fn update(&self, name: String, db: &PgPool) -> Result<Self> {
        Ok(
            query_as("UPDATE roles SET name = $2 WHERE id = $1 RETURNING *")
                .bind(self.id)
                .bind(name)
                .fetch_one(db)
                .await?,
        )
    }

    pub async fn deactivate(&self, db: &PgPool) -> Result<Self> {
        Ok(
            query_as("UPDATE roles SET deleted_at = $1 WHERE id = $2 RETURNING *")
                .bind(Local::now())
                .bind(self.id)
                .fetch_one(db)
                .await?,
        )
    }

    pub async fn permissions(&self, db: &PgPool) -> Result<Vec<Permission>> {
        Ok(query_as(
            "
            SELECT p.* FROM permissions p
            JOIN roles_permissions rp ON rp.permission_id = p.id 
            JOIN roles r ON rp.role_id = r.id 
            WHERE r.id = $1
        ",
        )
        .bind(self.id)
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

#[derive(Serialize, Deserialize, FromRow, Debug, Default)]
pub struct Permission {
    pub id: i32,
    pub name: String,
    pub created_at: DateTime<Local>,
    pub updated_at: Option<DateTime<Local>>,
    pub deleted_at: Option<DateTime<Local>>,
}

impl Permission {
    pub async fn create(name: String, db: &PgPool) -> Result<Self> {
        Ok(
            query_as("INSERT INTO permissions (name) VALUES ($1) RETURNING *")
                .bind(name)
                .fetch_one(db)
                .await?,
        )
    }

    pub async fn find(id: i32, db: &PgPool) -> Result<Self> {
        Ok(query_as("SELECT * FROM permissions WHERE id = $1")
            .bind(id)
            .fetch_one(db)
            .await?)
    }

    pub async fn all(db: &PgPool) -> Result<Vec<Self>> {
        Ok(query_as("SELECT * FROM permissions").fetch_all(db).await?)
    }

    pub async fn update(&self, name: String, db: &PgPool) -> Result<Self> {
        Ok(
            query_as("UPDATE permissions SET name = $2 WHERE id = $1 RETURNING *")
                .bind(self.id)
                .bind(name)
                .fetch_one(db)
                .await?,
        )
    }

    pub async fn deactivate(&self, db: &PgPool) -> Result<Self> {
        Ok(
            query_as("UPDATE permissions SET deleted_at = $1 WHERE id = $2 RETURNING *")
                .bind(Local::now())
                .bind(self.id)
                .fetch_one(db)
                .await?,
        )
    }

    pub async fn roles(&self, db: &PgPool) -> Result<Vec<Role>> {
        Ok(query_as(
            "SELECT r.* FROM roles r
                JOIN roles_permissions rp ON rp.role_id = r.id 
                JOIN permissions p ON rp.permission_id = p.id 
                WHERE p.id = $1",
        )
        .bind(self.id)
        .fetch_all(db)
        .await?)
    }

    pub async fn has_role(&self, role_id: i32, db: &PgPool) -> Result<bool> {
        Ok(self.roles(db).await?.into_iter().any(|r| r.id == role_id))
    }
}

// SELECT users.*,
//     JSON_AGG(user_roles.roles_permissions) AS roles
//     FROM (
//         SELECT
//         users.id,
//         JSON_BUILD_OBJECT(
//         'role', roles.*,
//         'permissions', JSON_AGG(permissions.*)
//         ) as roles_permissions
//         FROM users
//         LEFT JOIN users_roles ON users_roles.user_id = users.id
//         LEFT JOIN roles ON roles.id = users_roles.role_id
//         LEFT JOIN roles_permissions ON roles_permissions.role_id = roles.id
//         LEFT JOIN permissions ON permissions.id = roles_permissions.permission_id
//         WHERE users.id = $1
//         GROUP BY users.id, roles.id
//         ) as user_roles
//         JOIN users ON users.id = user_roles.id
//         GROUP BY users.id;
