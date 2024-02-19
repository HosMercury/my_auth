mod extractors;
mod middlewares;
mod users;
mod web;

use std::env;

use axum::middleware;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use sqlx::{postgres::PgPoolOptions, PgPool};
use time::Duration;
use tower_http::services::ServeDir;
use tower_sessions::{cookie::SameSite, Expiry, SessionManagerLayer};
use tower_sessions_redis_store::{fred::prelude::*, RedisStore};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use web::{auth, dashboard, oauth};

#[derive(Clone)]
struct AppState {
    db: PgPool,
    client: BasicClient,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "axum_login=debug,tower_sessions=debug,sqlx=warn,tower_http=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

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

    /////////////////////////  State  /////////////////////////
    let state = AppState { db, client };

    let app = dashboard::router()
        .layer(middleware::from_fn(middlewares::auth_middlware))
        .merge(auth::router())
        .merge(oauth::router())
        .layer(session_layer)
        .with_state(state)
        .nest_service("/assets", ServeDir::new("assets"));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
