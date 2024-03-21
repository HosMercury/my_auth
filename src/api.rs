use axum::{middleware, Router};
use crate::AppState;

pub mod client_auth;
pub mod main;

pub fn router(app_state: &AppState) -> Router<AppState> {
    Router::new()
        .nest("/api", main::router().merge(client_auth::router()))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            middlwares::auth,
        ))
}

pub mod middlwares {
    use axum::{
        extract::{Request, State},
        http::{self, StatusCode},
        middleware::Next,
        response::{IntoResponse, Response},
    };
    use sqlx::query;

    use crate::AppState;
    pub async fn auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
        let auth_header = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|header| header.to_str().ok());

        match auth_header {
            Some(api_token) => {
                let result = query!(
                    "SELECT access_token FROM users 
                    WHERE access_token = $1 
                    AND provider = $2 
                    AND deleted_at IS NULL",
                    api_token.replace("Bearer", "").trim().to_string(),
                    "api"
                )
                .fetch_one(&state.db)
                .await;

                match result {
                    Ok(_) => next.run(req).await,
                    Err(_) => StatusCode::UNAUTHORIZED.into_response(),
                }
            }
            None => StatusCode::UNAUTHORIZED.into_response(),
        }
    }
}
