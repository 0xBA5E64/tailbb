use axum::extract::State;
use axum_extra::extract::CookieJar;
use handlebars::{DirectorySourceOptions, Handlebars};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;
use uuid::Uuid;

#[allow(dead_code)]
pub struct AppState<'a> {
    pub host: String,
    pub db_url: String,
    pub db_pool: PgPool,
    pub templates: Handlebars<'a>,
    pub session_timeout: i64,
}

impl AppState<'_> {
    pub async fn new() -> Self {
        let host: String = std::env::var("HOST").expect("No HOST Specified");

        let db_url: String = std::env::var("DATABASE_URL").expect("No DATABASE_URL Specified");

        let db_pool = PgPoolOptions::new()
            .connect(db_url.as_str())
            .await
            .expect("DB connection failed");

        let mut templates = Handlebars::new();
        templates.set_dev_mode(true);
        // This is silly but DirectorySourceOptionsBuilder doesn't seem to exist
        //let mut dop = DirectorySourceOptions::default();
        //dop.tpl_extension = ".html".to_string();
        templates
            .register_templates_directory("templates/", DirectorySourceOptions::default())
            .unwrap();

        let session_timeout: i64 = std::env::var("SESSION_TIMEOUT")
            .expect("No SESSION_TIMEOUT Specified")
            .parse()
            .unwrap();

        Self {
            host,
            db_url,
            db_pool,
            templates,
            session_timeout,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub password_hash: String,
    pub password_salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct Post {
    pub id: Uuid,
    pub user_id: Uuid,
    pub category_id: Uuid,
    pub title: String,
    pub body: String,
    pub created_on: time::OffsetDateTime,
}

#[derive(Serialize, Deserialize)]
pub struct Category {
    pub id: Uuid,
    pub name: String,
    pub posts: Option<Vec<Post>>,
}

pub async fn get_user_from_token(
    app_state: &State<Arc<AppState<'_>>>,
    cookie_jar: &CookieJar,
) -> Option<User> {
    match cookie_jar.get("token") {
        Some(cookie) => {
            sqlx::query_as!(User,
                "SELECT * FROM Users WHERE id = (SELECT user_id FROM UserTokens WHERE token = $1 LIMIT 1) LIMIT 1",
                cookie.value_trimmed().parse::<Uuid>().unwrap_or_default()
                ).fetch_optional(&app_state.db_pool).await.unwrap()
            }
        None => None
    }
}

// TODO: This should be done as a middleware
pub async fn get_user_session(
    app_state: &State<Arc<AppState<'_>>>,
    cookie_jar: &CookieJar,
) -> Option<User> {
    let token: Option<Uuid> = match cookie_jar.get("token") {
        Some(cookie) => Some(cookie.value_trimmed().parse::<Uuid>().unwrap_or_default()),
        None => return None,
    };

    let session = match sqlx::query!("SELECT * FROM UserTokens WHERE token = $1 LIMIT 1", token)
        .fetch_optional(&app_state.db_pool)
        .await
        .unwrap()
    {
        Some(s) => s,
        None => return None,
    };

    let session_age: time::Duration = time::OffsetDateTime::now_utc() - session.last_active;
    let session_valid: bool = session_age.whole_seconds() < app_state.session_timeout;

    if !session_valid {
        sqlx::query!("DELETE FROM UserTokens WHERE token = $1", token)
            .execute(&app_state.db_pool)
            .await
            .unwrap();
    }

    sqlx::query!(
        "UPDATE UserTokens SET last_active = now() WHERE token = $1",
        token
    )
    .execute(&app_state.db_pool)
    .await
    .unwrap();

    let user = sqlx::query_as!(
        User,
        "SELECT * FROM Users WHERE id = $1 LIMIT 1",
        session.user_id
    )
    .fetch_one(&app_state.db_pool)
    .await
    .unwrap();

    Some(user)
}
