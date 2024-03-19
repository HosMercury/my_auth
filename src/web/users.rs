use crate::users::User;
use crate::AppState;
use askama::Template;
use axum::{routing::get, Router};
use rust_i18n::locale;

#[derive(Template)]
#[template(path = "pages/users/show.html")]
pub struct UserInfoTemplate {
    title: String,
    username: String,
    locale: String,
    user: User,
}

pub fn router() -> Router<AppState> {
    Router::new().nest(
        "/users",
        Router::new().route("/:id", get(self::get::user_info)),
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

    pub async fn user_info(
        auth_user: User,
        messages: Messages,
        Path(id): Path<Uuid>,
        State(state): State<AppState>,
    ) -> impl IntoResponse {
        let result = User::find_by_id(id, &state.db).await;

        match result {
            Ok(record) => match record {
                Some(user) => UserInfoTemplate {
                    title: format!("Show user {}", user.name),
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
