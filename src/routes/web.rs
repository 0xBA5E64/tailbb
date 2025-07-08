use argon2::PasswordHash;
use argon2::password_hash::rand_core::OsRng;
use axum::http::{Response, StatusCode};
use axum_extra::extract::CookieJar;
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::Form;
use axum::extract::{Path, State};
use axum::response::IntoResponse;

use tailbb::{AppState, Category, Post, get_user_from_token, get_user_session};

pub async fn view_hw(
    app_state: State<Arc<AppState<'_>>>,
    cookie_jar: CookieJar,
) -> impl IntoResponse {
    get_user_session(&app_state, &cookie_jar).await;

    Response::builder()
        .status(StatusCode::OK)
        .body(
            app_state
                .templates
                .render(
                    "basic",
                    &json!({
                        "content": "Hello World! This is the page",
                        "user": get_user_from_token(&app_state, &cookie_jar).await
                    }),
                )
                .unwrap(),
        )
        .unwrap()
}

pub async fn view_posts(
    app_state: State<Arc<AppState<'_>>>,
    cookie_jar: CookieJar,
) -> impl IntoResponse {
    let mut categories: Vec<Category> = sqlx::query!("SELECT id, name FROM Categorys;")
        .fetch_all(&app_state.db_pool)
        .await
        .unwrap()
        .iter()
        .map(|x| Category {
            id: x.id,
            name: x.name.clone(),
            posts: Some(Vec::new()),
        })
        .collect();

    for cat in &mut categories {
        cat.posts = Some(sqlx::query_as!(
                    Post,
                    "SELECT *, uuid_extract_timestamp(id) as \"created_on!\" FROM Posts WHERE category_id = $1 ORDER BY uuid_extract_timestamp(id) DESC",
                    cat.id
                )
                .fetch_all(&app_state.db_pool)
                .await
                .unwrap())
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(
            app_state
                .templates
                .render("post-list", &json!({"user": get_user_from_token(&app_state, &cookie_jar).await, "categories": categories}))
                .unwrap(),
        )
        .unwrap()
}

pub async fn view_post(
    app_state: State<Arc<AppState<'_>>>,
    cookie_jar: CookieJar,
    Path(post_id): Path<Uuid>,
) -> impl IntoResponse {
    let post = sqlx::query_as!(
        Post,
        "SELECT *, uuid_extract_timestamp(id) as \"created_on!\" FROM Posts WHERE id = $1;",
        post_id
    )
    .fetch_one(&app_state.db_pool)
    .await
    .expect("Failed to fetch post");

    Response::builder()
        .status(StatusCode::OK)
        .body(
            app_state
                .templates
                .render("post-view", &json!({"user": get_user_from_token(&app_state, &cookie_jar).await,"post": post}))
                .unwrap(),
        )
        .unwrap()
}

pub async fn view_post_form(
    app_state: State<Arc<AppState<'_>>>,
    cookie_jar: CookieJar,
) -> impl IntoResponse {
    let user = match get_user_from_token(&app_state, &cookie_jar).await {
        Some(u) => u,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("You must be logged in to post".to_string())
                .unwrap();
        }
    };

    let categories: Vec<Category> = sqlx::query!("SELECT *, null AS posts FROM Categorys;")
        .fetch_all(&app_state.db_pool)
        .await
        .unwrap()
        .iter()
        .map(|x| Category {
            id: x.id,
            name: x.name.clone(),
            posts: None,
        })
        .collect();

    Response::builder()
        .status(StatusCode::OK)
        .body(
            app_state
                .templates
                .render(
                    "post-form",
                    &json!({"user": user, "categories": categories}),
                )
                .unwrap(),
        )
        .unwrap()
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct NewPostForm {
    title: String,
    body: String,
    category: Uuid,
}

pub async fn new_post(
    app_state: State<Arc<AppState<'_>>>,
    cookie_jar: CookieJar,
    Form(form): Form<NewPostForm>,
) -> impl IntoResponse {
    let title = &form.title;
    let body = &form.body;

    let user = match get_user_from_token(&app_state, &cookie_jar).await {
        Some(u) => u,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("You must be logged in to post".to_string())
                .unwrap();
        }
    };

    println!("New Post: {title}, {body}");

    let query = sqlx::query!(
        "INSERT INTO Posts (title, body, user_id, category_id) VALUES ($1, $2, $3, $4) RETURNING id;",
        form.title,
        form.body,
        user.id,
        form.category
    ).fetch_one(&app_state.db_pool).await;

    match query {
        Ok(r) => Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header("Location", format!("/posts/{}", r.id))
            .body("".to_string())
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("{e}"))
            .unwrap(),
    }
}

pub async fn signup_view(
    app_state: State<Arc<AppState<'_>>>,
    cookie_jar: CookieJar,
) -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .body(
            app_state
                .templates
                .render(
                    "signup",
                    &json!({"user": get_user_from_token(&app_state, &cookie_jar).await}),
                )
                .unwrap(),
        )
        .unwrap()
}

pub async fn signup_handler(
    app_state: State<Arc<AppState<'_>>>,
    form: Form<LoginFormData>,
) -> impl IntoResponse {
    if sqlx::query!("SELECT name FROM Users WHERE name = $1", &form.username)
        .fetch_optional(&app_state.db_pool)
        .await
        .unwrap()
        .is_some()
    {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("User already exists".to_string())
            .unwrap();
    }
    // TODO: Username validation, should be strictly limited regarding special characters

    let a2 = Argon2::default();
    let pw_salt = SaltString::generate(OsRng);
    let pw_hash = a2
        .hash_password(form.password.as_bytes(), &pw_salt)
        .unwrap();

    let new_user = sqlx::query!(
        "INSERT INTO Users (name, password_salt, password_hash) VALUES ($1, $2, $3) RETURNING id;",
        form.username,
        pw_salt.to_string(),
        pw_hash.to_string()
    )
    .fetch_one(&app_state.db_pool)
    .await
    .unwrap();

    let session_token = sqlx::query!(
        "INSERT INTO UserTokens (user_id) VALUES ($1) RETURNING token;",
        new_user.id,
    )
    .fetch_one(&app_state.db_pool)
    .await
    .expect("Failed to insert user token")
    .token;

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("Location", "/")
        .header("Set-Cookie", format!("token={session_token}"))
        .body("Login Sucessful, redirecting...\n".to_string())
        .unwrap()
}

pub async fn login_view(app_state: State<Arc<AppState<'_>>>) -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .body(app_state.templates.render("login", &json!({})).unwrap())
        .unwrap()
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct LoginFormData {
    username: String,
    password: String,
    invite: Option<String>,
}

pub async fn login_handler(
    app_state: State<Arc<AppState<'_>>>,
    form: Form<LoginFormData>,
) -> impl IntoResponse {
    let db_user = match sqlx::query!("SELECT * FROM Users WHERE name = $1;", &form.username,)
        .fetch_optional(&app_state.db_pool)
        .await
        .unwrap()
    {
        Some(e) => e,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("User not found".to_string())
                .unwrap();
        } // Todo: Maybe don't announce this publicly
    };

    let a2 = Argon2::default();
    let salt_str = SaltString::from_b64(&db_user.password_salt).unwrap();
    let db_hash = PasswordHash::new(&db_user.password_hash)
        .unwrap()
        .hash
        .unwrap();
    let rq_hash = a2
        .hash_password(form.password.as_bytes(), &salt_str)
        .expect("Hashing failed")
        .hash
        .unwrap();

    if db_hash != rq_hash {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body("Invalid Password".to_string())
            .unwrap(); // Todo: Maybe don't announce this publicly
    }

    let session_token = sqlx::query!(
        "INSERT INTO UserTokens (user_id) VALUES ($1) RETURNING token;",
        &db_user.id,
    )
    .fetch_one(&app_state.db_pool)
    .await
    .expect("Failed to insert user token")
    .token;

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("Location", "/")
        .header("Set-Cookie", format!("token={session_token}"))
        .body("Login Sucessful, redirecting...\n".to_string())
        .unwrap()
}

pub async fn logout_handler(
    app_state: State<Arc<AppState<'_>>>,
    cookie_jar: CookieJar,
) -> impl IntoResponse {
    let token: Uuid = match cookie_jar.get("token") {
        Some(c) => Uuid::from_str(c.value_trimmed()).unwrap(),
        None => {
            return Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("Location", "/")
                .body("".to_string())
                .unwrap();
        }
    };

    let _query = sqlx::query!("DELETE FROM UserTokens WHERE token = $1", token)
        .fetch_optional(&app_state.db_pool)
        .await
        .unwrap();

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("Set-Cookie", "token=")
        .header("Location", "/")
        .body("Logged out, redirecting...".to_string())
        .unwrap()
}
