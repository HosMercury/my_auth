use crate::{web::AuthUser, web::USER_SESSION_KEY};
use askama_axum::IntoResponse;
use axum::{
    extract::{Query, Request},
    middleware::Next,
    response::{Redirect, Response},
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

pub async fn auth(session: Session, request: Request, next: Next) -> Response {
    match session.get::<AuthUser>(USER_SESSION_KEY).await.unwrap() {
        Some(_) => next.run(request).await,
        None => Redirect::to("/signin").into_response(),
    }
}

#[allow(unused)]
pub async fn is_authenticated(session: Session, request: Request, next: Next) -> Response {
    match session.get::<AuthUser>(USER_SESSION_KEY).await.unwrap() {
        Some(_) => Redirect::to("/").into_response(),
        None => next.run(request).await,
    }
}

/////////////////////  Locale  //////////////////
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    En,
    Ar,
}

#[derive(Serialize, Deserialize)]
struct LocaleQuery {
    locale: Locale,
}

const LOCALE_SESSION_KEY: &str = "locale";

pub async fn locale(session: Session, request: Request, next: Next) -> Response {
    let locale_query = Query::<LocaleQuery>::try_from_uri(request.uri());

    match locale_query {
        Ok(q) => {
            let path = request.uri().path();

            let locale_str = match q.0.locale {
                Locale::En => "en",
                Locale::Ar => "ar",
            };

            rust_i18n::set_locale(locale_str);

            session
                .insert(LOCALE_SESSION_KEY, locale_str)
                .await
                .expect("session failed to insert locale");

            Redirect::to(path).into_response()
        }
        Err(_) => {
            match session.get::<String>(LOCALE_SESSION_KEY).await.unwrap() {
                Some(locale) => {
                    rust_i18n::set_locale(locale.as_ref());
                }
                None => (),
            }
            next.run(request).await
        }
    }
}
