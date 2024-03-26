use super::middlwares::auth;
use crate::users::{self, Credentials, PasswordCreds, SignUp, User};
use crate::web::session::save_session_user;
use crate::AppState;
use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::State,
    middleware,
    response::Redirect,
    routing::{get, post},
    Form, Router,
};

use axum_messages::{Message, Messages};
use rust_i18n::locale;
use tower_sessions::Session;
use validator::Validate;

#[derive(Template)]
#[template(path = "pages/signin.html")]
struct SigninTemplate {
    title: String,
    messages: Vec<Message>,
    locale: String,
    previous_data: PasswordCreds,
}

#[derive(Template)]
#[template(path = "pages/signup.html")]
pub struct SignupTemplate {
    title: String,
    messages: Vec<Message>,
    locale: String,
    previous_data: SignUp,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/signout", post(self::post::signout))
        .layer(middleware::from_fn(auth))
        .route("/signup", get(self::get::signup).post(self::post::signup))
        .route("/signin", get(self::get::signin).post(self::post::password))
}

mod get {
    use super::*;
    use crate::web::session::{get_previous_data, get_session_validation_messages};

    #[axum::debug_handler]
    pub async fn signin(messages: Messages, session: Session) -> SigninTemplate {
        SigninTemplate {
            title: t!("sign_in").to_string(),
            messages: get_session_validation_messages(&messages),
            locale: locale().to_string(),
            previous_data: get_previous_data::<PasswordCreds>(&session).await,
        }
    }

    #[axum::debug_handler]
    pub async fn signup(messages: Messages, session: Session) -> SignupTemplate {
        SignupTemplate {
            title: t!("sign_up").to_string(),
            messages: get_session_validation_messages(&messages),
            locale: locale().to_string(),
            previous_data: get_previous_data::<SignUp>(&session).await,
        }
    }
}

mod post {
    use super::*;
    use crate::{
        validations::{validate_username_exists, validation_messages},
        web::session::{save_previous_data, save_session_validation_messages},
    };

    pub async fn password(
        session: Session,
        messages: Messages,
        State(state): State<AppState>,
        Form(payload): Form<PasswordCreds>,
    ) -> impl IntoResponse {
        // No validation needed here -- think again
        match User::authenticate(
            Credentials::Password(payload.clone()),
            &state.db,
            state.client,
        )
        .await
        {
            Ok(Some(user)) => {
                save_session_user(user, &session).await;
                Redirect::to("/").into_response()
            }
            Ok(None) => {
                messages.error(t!("errors.invalid_credentials"));
                save_previous_data(&payload, &session).await;
                Redirect::to("/signin").into_response()
            }
            Err(_) => {
                messages.error(t!("errors.system_error"));
                save_previous_data(&payload, &session).await;
                Redirect::to("/signin").into_response()
            }
        }
    }

    pub async fn signup(
        messages: Messages,
        session: Session,
        State(AppState { db, .. }): State<AppState>,
        Form(payload): Form<SignUp>,
    ) -> Redirect {
        save_previous_data(&payload, &session).await;

        match payload.validate() {
            Ok(_) => {
                match User::register(users::RegisterUser::WebUser(payload.clone()), &db).await {
                    Ok(_) => Redirect::to("/"),
                    Err(_) => {
                        messages.error(t!("errors.system_error"));
                        Redirect::to("/signin")
                    }
                }
            }
            Err(mut e) => {
                // async validations -- does not work with custom validator crate
                let errors = validate_username_exists(&mut e, &payload.username, &db).await;
                let errs = validation_messages(&errors);
                save_session_validation_messages(&errs, &messages);
                Redirect::to("/signup")
            }
        }
    }

    pub async fn signout(session: Session) -> Redirect {
        session.flush().await.unwrap();
        Redirect::to("/signin")
    }
}
