use dotenvy::dotenv;
use std::sync::Arc;

#[allow(unused_imports)]
use axum::{
    Router,
    routing::{get, post},
};
use tower_http::services::ServeDir;

use tailbb::AppState;

mod routes;

#[tokio::main]
async fn main() {
    dotenv().expect(".env not found");

    let app_state: AppState = AppState::new().await;

    sqlx::migrate!()
        .run(&app_state.db_pool)
        .await
        .expect("Failed to perform migrations");

    let listener = tokio::net::TcpListener::bind(&app_state.host)
        .await
        .unwrap();

    let app = Router::new()
        .merge(routes::get_web_router())
        // STATIC CONTENT
        .nest_service("/static", ServeDir::new("./static"))
        // STATE
        .with_state(Arc::new(app_state));

    axum::serve(listener, app).await.unwrap();
}
