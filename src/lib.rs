use axum::extract::State;
use axum_extra::extract::CookieJar;
use handlebars::{DirectorySourceOptions, Handlebars};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgPoolOptions};
use core::fmt;
use std::{str::FromStr, sync::Arc};
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Clone)]
pub struct AppState {
    pub host: String,
    pub db_url: String,
    pub db_pool: PgPool,
    pub templates: Handlebars<'static>,
    pub session_timeout: i64,
}

impl AppState {
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

#[derive(Serialize, Deserialize, Clone, Debug)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UserState {
    ValidSession(User),
    ExpiredToken,
    InvalidToken,
    NoToken,
}

pub enum UsernameError {
    WhitespacePadding,
    InnerWhitespace,
    SpecialCharacters,
    Empty,
}

impl fmt::Display for UsernameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::WhitespacePadding => write!(f, "Username cannot have whitespace padding"),
            Self::InnerWhitespace => write!(f, "Username cannot have whitespace in it"),
            Self::SpecialCharacters => write!(f, "Username cannot have special characters"),
            Self::Empty => write!(f, "Username cannot be empty"),
        }
    }
}

pub fn validate_username(username: &str) -> Result<(), UsernameError> {
    // Verify that username isn't empty or padded
    if username != username.trim() {
        return Err(UsernameError::WhitespacePadding);
    }

    // Verify that username doesn't have any whitespace in it
    if username.chars().any(|c: char| c.is_whitespace()) {
        return Err(UsernameError::InnerWhitespace);
    }

    // Verify that username doesn't have any special characters
    if username
        .chars()
        .all(|c: char| (!c.is_ascii_alphanumeric() || ".-_".contains(c)))
    {
        return Err(UsernameError::SpecialCharacters);
    }

    if username.trim().is_empty() {
        return Err(UsernameError::Empty);
    }
    Ok(())
}

pub async fn get_user_session(
    app_state: &State<Arc<AppState>>,
    cookie_jar: &CookieJar,
) -> UserState {
    let token: Uuid = match cookie_jar
        .get("token")
        .and_then(|v| {
            let trimmed = v.value_trimmed();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .and_then(|value| Uuid::from_str(value).ok())
    {
        Some(token) => token,
        None => return UserState::NoToken,
    };

    let session = match sqlx::query!("SELECT * FROM UserTokens WHERE token = $1 LIMIT 1", token)
        .fetch_optional(&app_state.db_pool)
        .await
        .unwrap()
    {
        Some(s) => s,
        None => return UserState::InvalidToken,
    };

    let session_age: time::Duration = time::OffsetDateTime::now_utc() - session.last_active;
    let session_valid: bool = session_age.whole_seconds() < app_state.session_timeout;

    if !session_valid {
        sqlx::query!("DELETE FROM UserTokens WHERE token = $1", token)
            .execute(&app_state.db_pool)
            .await
            .unwrap();
        return UserState::ExpiredToken;
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

    UserState::ValidSession(user)
}
