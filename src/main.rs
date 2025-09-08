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
    dotenv().ok();

    let app_state: Arc<AppState> = Arc::new(AppState::new().await);

    sqlx::migrate!()
        .run(&app_state.db_pool)
        .await
        .expect("Failed to perform migrations");

    let listener = tokio::net::TcpListener::bind(&app_state.host)
        .await
        .unwrap();

    let app = Router::new()
        .merge(routes::get_web_router(&app_state))
        // STATIC CONTENT
        .nest_service("/static", ServeDir::new("./static"))
        // STATE
        .with_state(app_state);

    let server = axum::serve(listener, app);

    println!(
        "Serving on: http://{ip}:{port}",
        ip = server.local_addr().unwrap().ip(),
        port = server.local_addr().unwrap().port()
    );

    server.await.unwrap();
}
