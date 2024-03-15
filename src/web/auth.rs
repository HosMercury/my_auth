use crate::users::{self, Credentials, PasswordCreds, SignUp, User};
use crate::validations::get_messages;
use crate::web::save_session_user;
use crate::{middlewares, validations, AppState};
use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::State,
    middleware,
    response::Redirect,
    routing::{get, post},
    Form, Router,
};
use axum_messages::Messages;
use rust_i18n::locale;
use tower_sessions::Session;
use validations::get_previous_data;
use validations::save_previous_data;
use validator::Validate;

#[derive(Template)]
#[template(path = "pages/signin.html")]
struct SigninTemplate {
    title: String,
    messages: Vec<String>,
    locale: String,
    previous_data: PasswordCreds,
}

#[derive(Template)]
#[template(path = "pages/signup.html")]
pub struct SignupTemplate {
    title: String,
    messages: Vec<String>,
    locale: String,
    previous_data: SignUp,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/signout", post(self::post::signout))
        .layer(middleware::from_fn(middlewares::auth))
        .route("/signup", get(self::get::signup).post(self::post::signup))
        .route("/signin", get(self::get::signin).post(self::post::password))
}

mod get {
    use super::*;

    #[axum::debug_handler]
    pub async fn signin(messages: Messages, session: Session) -> SigninTemplate {
        SigninTemplate {
            title: t!("sign_in").to_string(),
            messages: get_messages(messages),
            locale: locale().to_string(),
            previous_data: get_previous_data::<PasswordCreds>(&session).await,
        }
    }

    #[axum::debug_handler]
    pub async fn signup(messages: Messages, session: Session) -> SignupTemplate {
        SignupTemplate {
            title: t!("sign_up").to_string(),
            messages: get_messages(messages),
            locale: locale().to_string(),
            previous_data: get_previous_data::<SignUp>(&session).await,
        }
    }
}

mod post {
    use super::*;

    pub async fn password(
        session: Session,
        messages: Messages,
        State(AppState { db, client }): State<AppState>,
        Form(payload): Form<PasswordCreds>,
    ) -> impl IntoResponse {
        // No validation needed here -- think again
        match User::authenticate(Credentials::Password(payload.clone()), db, client).await {
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
                messages.error(t!("system_error"));
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
        match payload.validate() {
            Ok(_) => {
                match User::register(users::RegisterUser::WebUser(payload.clone()), db).await {
                    Ok(user) => {
                        save_session_user(user, &session).await;
                        Redirect::to("/")
                    }
                    Err(_) => {
                        messages.error(t!("system_error"));
                        save_previous_data(&payload, &session).await;
                        Redirect::to("/signin")
                    }
                }
            }
            Err(_) => {
                messages.error(t!("system_error"));
                save_previous_data(&payload, &session).await;
                Redirect::to("/signup")
            }
        }

        // Err(mut errs) => {
        //     if username_exists(payload.username.clone(), &db).await {
        //         errs.add(
        //             "username", // field name
        //             ValidationError {
        //                 code: "username".into(),
        //                 message: Some(t!("username_exists").into()),
        //                 params: [("username".into(), payload.username.into())]
        //                     .into_iter()
        //                     .collect(),
        //             },
        //         )
        //     }
        // }
    }

    pub async fn signout(session: Session) -> Redirect {
        session.flush().await.unwrap();
        Redirect::to("/signin")
    }
}
