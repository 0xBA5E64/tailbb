use axum::{
    body::Body,
    extract::State,
    http::{Response, StatusCode},
    response::IntoResponse,
};
use axum_extra::extract::CookieJar;
use core::fmt;
use handlebars::{DirectorySourceOptions, Handlebars};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;
use uuid::Uuid;

pub mod built_info {
    // The file has been placed there by the build script.
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(Clone, Serialize)]
pub struct BuildInfo {
    pub commit: String,
    pub head_ref: String,
    pub dirty: bool,
}
impl BuildInfo {
    pub async fn new() -> Option<Self> {
        let commit = match built_info::GIT_COMMIT_HASH {
            Some(e) => String::from(e),
            None => return None,
        };

        let head_ref = match built_info::GIT_HEAD_REF {
            Some(e) => String::from(e),
            None => return None,
        };

        let dirty = match built_info::GIT_DIRTY {
            Some(e) => bool::from(e),
            None => return None,
        };

        Some(Self {
            commit,
            head_ref,
            dirty,
        })
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct AppState {
    pub host: String,
    pub db_url: String,
    pub db_pool: PgPool,
    pub build_info: Option<BuildInfo>,
    pub templates: Handlebars<'static>,
    pub session_timeout: i64,
}

impl AppState {
    pub async fn new() -> Self {
        let host: String = std::env::var("HOST").unwrap_or("0.0.0.0:3000".to_string());

        let db_url: String = std::env::var("DATABASE_URL").expect("No DATABASE_URL Specified");

        let db_pool = PgPoolOptions::new()
            .connect(db_url.as_str())
            .await
            .expect("DB connection failed");

        let build_info = BuildInfo::new();

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
            build_info: build_info.await,
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

#[derive(PartialEq, Debug)]
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

impl IntoResponse for UsernameError {
    fn into_response(self) -> axum::response::Response {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("{self}")))
            .unwrap()
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
        .any(|c: char| !(c.is_ascii_alphanumeric() || ".-_".contains(c)))
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
        .and_then(|value| Uuid::parse_str(value).ok())
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

#[cfg(test)]
mod validate_username_tests {
    use super::{UsernameError, validate_username};

    #[test]
    fn valid() {
        assert!(validate_username("do-ria_3.12").is_ok());
        assert!(validate_username("Do ria! 312").is_err());
    }

    #[test]
    fn inner_whitespace() {
        assert_eq!(
            validate_username("doria 312"),
            Err(UsernameError::InnerWhitespace)
        );
    }

    #[test]
    fn whitespace_padding() {
        assert_eq!(
            validate_username("  do-ria_3.12"),
            Err(UsernameError::WhitespacePadding)
        );
        assert_eq!(
            validate_username("do-ria_3.12  "),
            Err(UsernameError::WhitespacePadding)
        );
    }

    #[test]
    fn special_characters() {
        assert_eq!(validate_username("do-ria_3.12"), Ok(()));
        assert_eq!(
            validate_username("do-ria+3.12"),
            Err(UsernameError::SpecialCharacters)
        );
    }
}
