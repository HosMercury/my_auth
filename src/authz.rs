use crate::users::User;
use anyhow::Result;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{query, Row};
use sqlx::{query_as, FromRow, PgPool};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt::Debug;

//User authorization impl
impl User {
    pub async fn roles(&self, db: &PgPool) -> Result<Vec<Role>> {
        // if no permissions - it will return empty vec
        Ok(query_as(
            "SELECT roles.* FROM roles 
                 JOIN users_roles ON  users_roles.role_id = roles.id
                 JOIN users       ON  users_roles.user_id = users.id
                 WHERE users.id = $1",
        )
        .bind(self.id)
        .fetch_all(db)
        .await?)
    }

    pub async fn permissions(&self, db: &PgPool) -> Result<Vec<Permission>> {
        // if no permissions - it will return empty vec
        Ok(query_as(
            "SELECT permissions.* FROM permissions
            JOIN roles_permissions ON roles_permissions.permission_id = permissions.id
            JOIN roles             ON roles_permissions.role_id       = roles.id
            JOIN users_roles       ON roles.id                        = users_roles.role_id
            JOIN users             ON users_roles.user_id             = users.id
            WHERE users.id = $1",
        )
        .bind(self.id)
        .fetch_all(db)
        .await?)
    }

    pub async fn has_role(&self, role_id: i32, db: &PgPool) -> Result<bool> {
        Ok(query(
            "SELECT COUNT(*) > 0 AS count FROM users_roles WHERE user_id = $1 and role_id = $2 ",
        )
        .bind(self.id)
        .bind(role_id)
        .map(|row: PgRow| row.try_get::<bool, _>("count").unwrap())
        .fetch_one(db)
        .await?)
    }

    pub async fn has_permission(&self, permission_id: i32, db: &PgPool) -> Result<bool> {
        Ok(query(
            "SELECT COUNT(*) > 0 AS count FROM users
            JOIN users_roles       ON users_roles.user_id             = users.id
            JOIN roles             ON users_roles.role_id             = roles.id
            JOIN roles_permissions ON roles_permissions.role_id       = roles.id
            JOIN permissions       ON roles_permissions.permission_id = permissions.id
            WHERE users.id = $1 AND permissions.id = $2;",
        )
        .bind(self.id)
        .bind(permission_id)
        .map(|row: PgRow| row.try_get::<bool, _>("count").unwrap())
        .fetch_one(db)
        .await?)
    }

    pub async fn with_roles(id: i32, db: &PgPool) -> Result<UserWithRoles> {
        let rows = sqlx::query(
            "SELECT users.*,
            roles.id AS role_id,
            roles.name AS role_name,
            roles.created_at AS role_created_at,
            roles.updated_at AS role_updated_at,
            roles.deleted_at AS role_deleted_at
            FROM users
            LEFT JOIN users_roles ON users_roles.user_id = users.id
            LEFT JOIN roles       ON users_roles.role_id = roles.id
            WHERE users.id = $1",
        )
        .bind(id)
        .fetch_all(db)
        .await?;

        let user = User::from_row(&rows[0])?;
        let mut roles: Vec<Role> = vec![];
        for row in rows {
            if let Ok(id) = row.try_get::<i32, _>("role_id") {
                let role = Role {
                    id,
                    name: row.try_get("role_name")?,
                    created_at: row.try_get("role_created_at")?,
                    updated_at: row.try_get("role_updated_at").unwrap_or(None),
                    deleted_at: row.try_get("role_deleted_at").unwrap_or(None),
                };
                roles.push(role);
            }
        }
        Ok(UserWithRoles { user, roles })
    }

    // Get the user and their roles and return permissions
    pub async fn with_roles_permissions(
        id: i32,
        db: &PgPool,
    ) -> Result<UserWithRolesWithPermissions> {
        let rows = query(
            "SELECT users.*,
                    
                    roles.id AS role_id,
                    roles.name AS role_name,
                    roles.created_at AS role_created_at,
                    roles.updated_at AS role_updated_at,
                    roles.deleted_at AS role_deleted_at,
                    
                    permissions.id AS permission_id,
                    permissions.name AS permission_name,
                    permissions.created_at AS permission_created_at,
                    permissions.updated_at AS permission_updated_at,
                    permissions.deleted_at AS permission_deleted_at
                FROM users
                LEFT JOIN users_roles       ON users.id                        = users_roles.user_id
                LEFT JOIN roles             ON users_roles.role_id             = roles.id
                LEFT JOIN roles_permissions ON roles.id                        = roles_permissions.role_id
                LEFT JOIN permissions       ON roles_permissions.permission_id = permissions.id
                    WHERE users.id = $1
                    GROUP BY users.id, roles.id, permissions.id;",
        )
        .bind(id)
        .fetch_all(db)
        .await?;
        let user = User::from_row(&rows[0])?;

        let mut roles: BTreeMap<i32, RoleWithPermissions> = BTreeMap::new();

        for row in rows {
            if let Ok(id) = row.try_get::<i32, _>("role_id") {
                let role = match roles.entry(id) {
                    Entry::Occupied(v) => v.into_mut(),
                    Entry::Vacant(v) => {
                        let role = RoleWithPermissions {
                            role: Role {
                                id,
                                name: row.try_get("role_name")?,
                                created_at: row.try_get("role_created_at")?,
                                updated_at: row.try_get("role_updated_at").unwrap_or(None),
                                deleted_at: row.try_get("role_deleted_at").unwrap_or(None),
                            },
                            permissions: vec![],
                        };
                        v.insert(role)
                    }
                };

                if let Ok(id) = row.try_get::<i32, _>("permission_id") {
                    let permission = Permission {
                        id,
                        name: row.get("permission_name"),
                        created_at: row.get("permission_created_at"),
                        updated_at: row.try_get("permission_updated_at").unwrap_or(None),
                        deleted_at: row.try_get("permission_deleted_at").unwrap_or(None),
                    };

                    role.permissions.push(permission);
                }
            }
        }
        let roles = roles.into_values().collect();
        Ok(UserWithRolesWithPermissions { user, roles })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserWithRoles {
    pub user: User,
    pub roles: Vec<Role>,
}

/// User - Roles - permissions --
#[derive(Serialize, Deserialize, Debug)]
pub struct UserWithRolesWithPermissions {
    pub user: User,
    pub roles: Vec<RoleWithPermissions>,
}

// Role -v-
#[derive(Debug, Deserialize, Serialize)]
pub struct RoleWithPermissions {
    pub role: Role,
    pub permissions: Vec<Permission>,
}

#[derive(Serialize, Deserialize, FromRow, Debug, Clone, Default)]
pub struct Role {
    pub id: i32,
    pub name: String,
    pub created_at: DateTime<Local>,
    pub updated_at: Option<DateTime<Local>>,
    pub deleted_at: Option<DateTime<Local>>,
}

// impl FromRow<'_, PgRow> for UserWithRoles {
//     fn from_row(row: &PgRow) -> sqlx::Result<Self> {
//         let user: User = User::from_row(row).expect("deser user failed");

//         let roles = row
//             .try_get::<Json<Vec<Role>>, _>("roles")
//             .map(|x| x.0)
//             .unwrap_or(vec![]);

//         println!("{:?}", roles);

//         Ok(Self { user, roles })
//     }
// }

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

////////////////////////////////////////////////////////////////////////
////////////////////////////////Draft SQls ///////////////////////////////////
////////////////////////////////////////////////////////////////////////
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

// WITH role_perms AS (
//     SELECT
//         roles.id AS role_id,
//         jsonb_build_object('role', roles.*, 'permissions', jsonb_agg(permissions.*)) AS role_permissions
//     FROM
//         roles
//         LEFT JOIN roles_permissions rp ON rp.role_id = roles.id
//         LEFT JOIN permissions ON rp.permission_id = permissions.id
//     GROUP BY
//         roles.id
// ),
// user_roles_permissions AS (
//     SELECT
//         users.*,
//         jsonb_build_object('roles', jsonb_agg(role_perms.role_permissions)) AS roles
//     FROM
//         users
//         LEFT JOIN users_roles ON users.id = users_roles.user_id
//         LEFT JOIN roles ON users_roles.role_id = roles.id
//         LEFT JOIN role_perms ON roles.id = role_perms.role_id
//     WHERE
//         users.id = $1
//     GROUP BY
//         users.id
// )
// SELECT
//     *
// FROM
//     user_roles_permissions;

// SELECT
// users.*,

// roles.id AS role_id,
// roles.name AS role_name,
// roles.created_at AS role_created_at,
// roles.updated_at AS role_updated_at,
// roles.deleted_at AS role_deleted_at,

// permissions.id AS permission_id,
// permissions.name AS permission_name,
// permissions.created_at AS permission_created_at,
// permissions.updated_at AS permission_updated_at,
// permissions.deleted_at AS permission_deleted_at
// FROM
// users
// LEFT JOIN users_roles ON users.id = users_roles.user_id
// LEFT JOIN roles ON users_roles.role_id = roles.id
// LEFT JOIN roles_permissions ON roles.id = roles_permissions.role_id
// LEFT JOIN permissions ON roles_permissions.permission_id = permissions.id
// WHERE users.id = $1
// GROUP BY
// users.id,
// roles.id,
// permissions.id;

// let role: RoleWithPermissions;
