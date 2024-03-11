use crate::users::AuthUser;
use crate::users::{Credentials, PasswordCreds, SignUp, User};
use crate::{utils, AppState};
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
use password_auth::generate_hash;
use sqlx::query;
use tower_sessions::Session;
use validator::Validate;

pub const USER_SESSION_KEY: &str = "user";

#[derive(Template)]
#[template(path = "pages/signin.html")]
pub struct SigninTemplate {
    pub title: String,
    pub messages: Vec<String>,
}

#[derive(Template)]
#[template(path = "pages/signup.html")]
pub struct SignupTemplate {
    pub title: String,
    pub messages: Vec<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/signout", post(self::post::signout))
        .layer(middleware::from_fn(utils::auth_middlware))
        .route("/signup", get(self::get::signup).post(self::post::signup))
        .route("/signin", get(self::get::signin).post(self::post::password))
}

mod get {
    use super::*;

    pub async fn signin(messages: Messages) -> SigninTemplate {
        let messages = messages
            .into_iter()
            .map(|message| format!("{}", message))
            .collect::<Vec<_>>();

        SigninTemplate {
            title: t!("sign_in").to_string(),
            messages,
        }
    }

    pub async fn signup(messages: Messages) -> SignupTemplate {
        // Should be separate function
        let messages = messages
            .into_iter()
            .map(|message| format!("{}", message))
            .collect::<Vec<_>>();

        SignupTemplate {
            title: t!("sign_up").to_string(),
            messages,
        }
    }
}

mod post {
    use self::utils::{flash_errors, username_exists};
    use super::*;
    use tokio::task;
    use validator::ValidationError;

    pub async fn signup(
        messages: Messages,
        session: Session,
        State(AppState { db, .. }): State<AppState>,
        Form(data): Form<SignUp>,
    ) -> Redirect {
        match data.validate() {
            Ok(_) => {
                let hashed_password = task::spawn_blocking(|| generate_hash(data.password))
                    .await
                    .unwrap();

                let result = query!(
                    r#"
                        INSERT INTO users (name, username, password)
                        VALUES ($1, $2, $3)
                        RETURNING username
                    "#,
                    data.name,
                    data.username.clone(),
                    hashed_password
                )
                .fetch_one(&db)
                .await;

                match result {
                    Ok(user) => {
                        let res =
                            query!("SELECT name FROM users WHERE username = $1", user.username)
                                .fetch_one(&db)
                                .await;

                        match res {
                            Ok(r) => {
                                session
                                    .insert(USER_SESSION_KEY, AuthUser { name: r.name })
                                    .await
                                    .expect("session failed to insert user name");

                                Redirect::to("/")
                            }
                            Err(_) => {
                                messages.error(t!("system_error"));
                                Redirect::to("/signup")
                            }
                        }
                    }
                    Err(_) => {
                        messages.error(t!("system_error"));
                        Redirect::to("/signup")
                    }
                }
            }
            Err(mut errs) => {
                if username_exists(data.username.clone(), &db).await {
                    errs.add(
                        "username", // field name
                        ValidationError {
                            code: "username".into(),
                            message: Some(t!("username_exists").into()),
                            params: [("username".into(), data.username.into())]
                                .into_iter()
                                .collect(),
                        },
                    )
                }
                flash_errors(errs, messages).await;
                Redirect::to("/signup")
            }
        }
    }

    pub async fn password(
        session: Session,
        messages: Messages,
        State(AppState { db, client }): State<AppState>,
        Form(creds): Form<PasswordCreds>,
    ) -> impl IntoResponse {
        match User::authenticate(Credentials::Password(creds.clone()), db, client, session).await {
            Ok(Some(_)) => Redirect::to("/").into_response(),
            Ok(None) => {
                // save msgs -- there is no user
                messages.error("These credentials do not match ours");
                Redirect::to("/signin").into_response()
            }
            Err(_) => {
                messages.error(t!("system_error"));
                Redirect::to("/signin").into_response()
            }
        }
    }

    pub async fn signout(session: Session) -> Redirect {
        session.flush().await.unwrap();
        Redirect::to("/signin")
    }
}
