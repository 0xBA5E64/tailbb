use std::sync::Arc;

use axum::{Router, routing::get};
use tailbb::AppState;

pub mod web;

// "Legacy"-style server-side rendered web frontend.
pub fn get_web_router() -> Router<Arc<AppState<'static>>> {
    Router::new()
        // Front Page
        .route("/", get(web::view_hw))
        // Auth
        .route("/signup", get(web::signup_view).post(web::signup_handler))
        .route("/login", get(web::login_view).post(web::login_handler))
        .route("/logout", get(web::logout_handler))
        // Posts
        .route("/posts", get(web::view_posts))
        .route("/posts/new", get(web::view_post_form).post(web::new_post))
        .route("/posts/{post_id}", get(web::view_post))
}
