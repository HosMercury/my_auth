mod handlers;
mod models;
mod validation;

use axum_messages::MessagesManagerLayer;
use handlers::user_handler;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::env;
use time::Duration;
use tower_sessions::{Expiry, SessionManagerLayer};
use tower_sessions_redis_store::{fred::prelude::*, RedisStore};

#[derive(Clone)]
struct AppState {
    app_name: &'static str,
    db: Pool<Postgres>,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().expect("error loading .env");
    ////////////////// SESSION //////////////////////////////
    let pool = RedisPool::new(RedisConfig::default(), None, None, None, 6).unwrap();
    pool.connect();
    pool.wait_for_connect().await.unwrap();
    let session_store = RedisStore::new(pool);
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::seconds(10)));
    ////////////////// DB //////////////////////////////
    let db_url: String = env::var("DATABASE_URL").unwrap();
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("error connection to db");
    ///////////// AXUM /////////////
    let shared_state = AppState {
        app_name: "Multi-Auth",
        db,
    };

    let app = user_handler::router()
        .layer(MessagesManagerLayer)
        .layer(session_layer)
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
