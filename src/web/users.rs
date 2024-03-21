use crate::users::User;
use crate::web::filters;
use crate::AppState;
use askama::Template;
use axum::{routing::get, Router};
use rust_i18n::locale;

#[derive(Template)]
#[template(path = "pages/users/index.html")]
pub struct IndexTemplate {
    title: String,
    username: String,
    locale: String,
    users: Vec<User>,
}

#[derive(Template)]
#[template(path = "pages/users/show.html")]
pub struct ShowTemplate {
    title: String,
    username: String,
    locale: String,
    user: User,
}

pub fn router() -> Router<AppState> {
    Router::new().nest(
        "/users",
        Router::new()
            .route("/", get(self::get::index))
            .route("/:uid", get(self::get::show)),
    )
}

pub mod get {
    use super::*;
    use crate::users::User;
    use askama_axum::IntoResponse;
    use axum::{
        extract::{Path, State},
        response::Redirect,
    };
    use axum_messages::Messages;
    use uuid::Uuid;

    pub async fn index(
        auth_user: User,
        messages: Messages,
        State(state): State<AppState>,
    ) -> impl IntoResponse {
        let result = User::all(&state.db).await;
        match result {
            Ok(users) => IndexTemplate {
                title: t!("users").to_string(),
                username: auth_user.name,
                locale: locale().to_string(),
                users,
            }
            .into_response(),
            Err(_) => {
                messages.error(t!("errors.errors.system_error"));
                Redirect::to("/users").into_response()
            }
        }
    }

    pub async fn show(
        auth_user: User,
        messages: Messages,
        Path(uid): Path<Uuid>,
        State(state): State<AppState>,
    ) -> impl IntoResponse {
        let result = User::find(uid, &state.db).await;

        match result {
            Ok(record) => match record {
                Some(user) => ShowTemplate {
                    title: t!("show_user", name = user.name).to_string(),
                    username: auth_user.name,
                    locale: locale().to_string(),
                    user,
                }
                .into_response(),
                None => {
                    messages.error(t!("errors.user_not_found"));
                    Redirect::to("/users").into_response()
                }
            },
            Err(_) => {
                messages.error(t!("errors.errors.system_error"));
                Redirect::to("/users").into_response()
            }
        }
    }
}
