use axum::Router;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::env;
use time::Duration;
use tower_sessions::{cookie::SameSite, Expiry, SessionManagerLayer};
use tower_sessions_redis_store::{fred::prelude::*, RedisStore};

use crate::web::auth;

pub struct App {
    db: PgPool,
    client: BasicClient,
}

#[derive(Clone)]
pub(crate) struct AppState {
    db: PgPool,
}

impl App {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv()?;

        //////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////// OAuth ///////////////////////////////////////////
        let client_id = env::var("CLIENT_ID")
            .map(ClientId::new)
            .expect("CLIENT_ID should be provided.");

        let client_secret = env::var("CLIENT_SECRET")
            .map(ClientSecret::new)
            .expect("CLIENT_SECRET should be provided");

        let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?;
        let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())?;

        let client = BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_redirect_uri(
                RedirectUrl::new("http://localhost:3000/oauth/callback".to_string())
                    .expect("Invalid redirect URL"),
            );

        //////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////  DB  ///////////////////////////////////////////
        let db_url: String = env::var("DATABASE_URL").unwrap();

        let db = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("error connection to db");

        sqlx::migrate!().run(&db).await?;

        Ok(Self { db, client })
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        //////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////  REDIS  ////////////////////////////////////////
        // Session layer.
        //
        // This uses `tower-sessions` to establish a layer that will provide the session
        // as a request extension.
        let pool = RedisPool::new(RedisConfig::default(), None, None, None, 6).unwrap();
        pool.connect();

        let session_store = RedisStore::new(pool);
        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_same_site(SameSite::Lax) // Ensure we send the cookie from the OAuth redirect.
            .with_expiry(Expiry::OnInactivity(Duration::days(1)));

        /////////////////////////   State   /////////////////////////
        let state = AppState { db: self.db };

        let app = Router::new()
            .merge(auth::router())
            .layer(session_layer)
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        axum::serve(listener, app.into_make_service()).await?;

        Ok(())
    }
}