use crate::AppState;
use axum::routing::post;
use axum::Router;

pub fn router() -> Router<AppState> {
    Router::new().route("/keygen", post(self::post::keygen))
}

mod get {}

mod post {
    use axum::extract::State;

    use crate::AppState;

    // #[debug_handler]
    pub async fn keygen(State(AppState { db, .. }): State<AppState>) -> &'static str {
        // match payload.validate() {
        //     Ok(s) => {
        //         println!("s ==> {:?}", s);
        //     }
        //     Err(errs) => {
        //         let errors = validation_errors(&errs).await;
        //         println!("{:#?}", errors);
        //     }
        // }

        // let key = os_key_gen().await;

        // println!("{}", key);
        ""
    }
}
