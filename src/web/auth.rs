use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::State;
use axum::middleware;
use axum::response::Redirect;
use axum::routing::post;
use axum::{routing::get, Form, Router};
use tower_sessions::Session;

use crate::users::{Credentials, PasswordCreds, SignUp, User};
use crate::{utils, AppState};

pub const USER_SESSION_KEY: &str = "user";

#[derive(Template)]
#[template(path = "pages/signin.html")]
pub struct SigninTemplate {
    pub title: &'static str,
    pub messages: Option<Vec<String>>,
}

#[derive(Template)]
#[template(path = "pages/signup.html")]
pub struct SignupTemplate {
    pub title: &'static str,
    pub messages: Option<Vec<String>>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/signup", get(self::get::signup).post(self::post::signup))
        .route("/signin", get(self::get::signin).post(self::post::password))
        .layer(middleware::from_fn(utils::is_authenticated_middlware))
        .route("/signout", post(self::post::signout))
}

mod get {
    use super::*;

    pub async fn signin() -> SigninTemplate {
        SigninTemplate {
            title: "sign in",
            messages: None,
        }
    }

    pub async fn signup() -> SignupTemplate {
        SignupTemplate {
            title: "Sign Up",
            messages: None,
        }
    }
}

mod post {
    use super::*;

    pub async fn signup(Form(signup): Form<SignUp>) {
        //
    }

    pub async fn password(
        session: Session,
        State(AppState { db, client }): State<AppState>,
        Form(creds): Form<PasswordCreds>,
    ) -> impl IntoResponse {
        match User::authenticate(Credentials::Password(creds.clone()), db, client, session).await {
            Ok(Some(_)) => Redirect::to("/").into_response(),
            Ok(None) => Redirect::to("/signin").into_response(),
            Err(_) => Redirect::to("/signin").into_response(),
        }
    }

    pub async fn signout(session: Session) -> Redirect {
        session.flush().await.unwrap();
        Redirect::to("/signin")
    }
}
