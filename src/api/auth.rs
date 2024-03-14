use axum::Router;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
    //.route("/signout", post(self::post::signout))
    // .layer(middleware::from_fn(middlewares::auth))
    // .route("/signup", post(self::post::signup))
    // .route("/signin", post(self::post::password))
}

mod get {}

mod post {}
