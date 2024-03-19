pub mod auth;
pub mod dashboard;
pub mod oauth;
pub mod users;

pub(crate) mod keygen {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::prelude::*;
    use rand::{thread_rng, RngCore};
    use rand_core::OsRng;

    #[allow(unused)]
    pub fn keygen() -> String {
        let mut key = [0u8; 64];
        thread_rng().fill_bytes(&mut key);
        URL_SAFE_NO_PAD.encode(&key)
    }

    // OS is secure
    pub fn os_keygen() -> String {
        let mut key = [0u8; 64];
        OsRng.fill_bytes(&mut key);
        BASE64_URL_SAFE_NO_PAD.encode(&key)
    }
}

mod session {
    use crate::users::User;
    use axum_messages::{Level, Message, Messages, Metadata};
    use oauth2::CsrfToken;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use serde_json::json;
    use std::collections::HashMap;
    use tower_sessions::Session;
    use uuid::Uuid;
    use validator::ValidationErrors;

    pub const PREVIOUS_DATA_SESSION_KEY: &str = "previous_data";
    pub const USER_SESSION_KEY: &str = "user";
    pub const CSRF_STATE_KEY: &str = "oauth.csrf-state";

    #[derive(Serialize, Deserialize)]
    pub struct AuthUser {
        pub id: Uuid,
        pub name: String,
    }

    impl AuthUser {
        #[allow(unused)]
        pub async fn is_authenticated(&self, session: Session) -> bool {
            session
                .get::<Self>(USER_SESSION_KEY)
                .await
                .unwrap()
                .is_some()
        }
    }

    pub async fn save_session_user(user: User, session: &Session) {
        session
            .insert(
                USER_SESSION_KEY,
                AuthUser {
                    id: user.id,
                    name: user.name,
                },
            )
            .await
            .expect("Saving user in session failed");
    }

    pub async fn save_session_csrf(csrf_token: CsrfToken, session: Session) {
        session
            .insert(CSRF_STATE_KEY, csrf_token)
            .await
            .expect("Session failed to insert oauth csrf token");
    }

    pub async fn save_previous_data<T: Serialize>(payload: &T, session: &Session) {
        session
            .insert(PREVIOUS_DATA_SESSION_KEY, payload)
            .await
            .expect("failed to inset payload");
    }

    // Get payload data from session
    pub async fn get_previous_data<T: DeserializeOwned + Default>(session: &Session) -> T {
        // get and remove
        match session
            .remove::<T>(PREVIOUS_DATA_SESSION_KEY)
            .await
            .expect("Faild to get payload from session")
        {
            Some(payload) => payload,
            None => T::default(),
        }
    }

    pub fn save_session_validation_messages(errors: &ValidationErrors, messages: &Messages) {
        errors.field_errors().iter().for_each(|(field, errs)| {
            let params: Metadata = HashMap::from([("field".to_string(), json!(field))]);
            errs.iter().for_each(|e| {
                messages.clone().push(
                    Level::Error,
                    e.message
                        .clone()
                        .unwrap_or(t!("errors.unknown_reason").into()),
                    Some(params.clone()),
                );
            });
        });
    }

    pub fn get_session_validation_messages(messages: &Messages) -> Vec<Message> {
        messages.clone().into_iter().map(|m| m).collect::<Vec<_>>()
    }
}

pub(crate) mod middlwares {
    use askama_axum::IntoResponse;
    use axum::{
        extract::{Query, Request},
        middleware::Next,
        response::Redirect,
    };
    use serde::{Deserialize, Serialize};
    use tower_sessions::Session;

    use super::session::{AuthUser, USER_SESSION_KEY};

    pub async fn auth(session: Session, request: Request, next: Next) -> impl IntoResponse {
        match session.get::<AuthUser>(USER_SESSION_KEY).await.unwrap() {
            Some(_) => next.run(request).await,
            None => Redirect::to("/signin").into_response(),
        }
    }

    #[allow(unused)]
    pub async fn is_authenticated(
        session: Session,
        request: Request,
        next: Next,
    ) -> impl IntoResponse {
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

    pub async fn locale(session: Session, request: Request, next: Next) -> impl IntoResponse {
        let locale_query = Query::<LocaleQuery>::try_from_uri(request.uri());

        match locale_query {
            Ok(query) => {
                let path = request.uri().path();

                let locale_str = match query.0.locale {
                    Locale::En => "en",
                    Locale::Ar => "ar",
                };

                println!("{}", locale_str);

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
}

mod extractors {
    use super::session::{AuthUser, USER_SESSION_KEY};
    use axum::{async_trait, extract::FromRequestParts, http::request::Parts, response::Redirect};
    use tower_sessions::Session;

    #[async_trait]
    impl<S> FromRequestParts<S> for AuthUser
    where
        S: Send + Sync,
    {
        type Rejection = Redirect;

        async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
            let user = parts
                .extensions
                .get::<Session>()
                .unwrap()
                .get::<AuthUser>(USER_SESSION_KEY)
                .await
                .unwrap();

            match user {
                Some(user) => Ok(AuthUser {
                    id: user.id,
                    name: user.name,
                }),
                None => Err(Redirect::to("/signin")),
            }
        }
    }
}
