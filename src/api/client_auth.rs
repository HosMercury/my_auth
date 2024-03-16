use crate::AppState;
use axum::routing::post;
use axum::Router;

pub fn router() -> Router<AppState> {
    Router::new().route("/register", post(self::post::register))
}

mod get {}

mod post {
    use axum::response::IntoResponse;
    use axum::{extract::State, Json};
    use serde_json::json;
    use validator::Validate;

    use crate::validations::json_validatio_errors;
    use crate::{
        users::{self, ApiUser, User},
        AppState,
    };

    #[axum::debug_handler]
    pub async fn register(
        State(AppState { db, .. }): State<AppState>,
        Json(payload): Json<ApiUser>,
    ) -> impl IntoResponse {
        match payload.validate() {
            Ok(_) => {
                match User::register(users::RegisterUser::ApiUser(payload.clone()), db).await {
                    Ok(_) => {
                        // will do the db stuff
                        // then send the response
                        "".into_response()
                    }
                    Err(_) => {
                        // send general system err as json
                        "".into_response()
                    }
                }
            }
            Err(mut e) => {
                // validate async username
                // send validation errors as json

                println!("json errs {:?}", e);

                Json(json!(e)).into_response()

                // async validations -- does not work with custom validator crate
                // let errors = validate_username(&mut e, &payload.username, &db).await;
                // let errs = validation_errors(&errors);
            }
        }
    }
}
