use argon2::PasswordHash;
use argon2::password_hash::rand_core::OsRng;
use axum::body::Body;
use axum::extract::{Extension, Query};
use axum::http::{Response, StatusCode};
use axum::middleware::Next;
use axum_extra::extract::{CookieJar, cookie::Cookie};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::Form;
use axum::extract::{Path, Request, State};
use axum::response::{IntoResponse, Redirect};

use tailbb::{AppState, Category, Post, UserState, get_user_session, validate_username};

#[axum::debug_middleware]
pub async fn auth_middleware(
    app_state: State<Arc<AppState>>,
    cookie_jar: CookieJar,
    mut req: Request,
    nxt: Next,
) -> Response<Body> {
    let user_state = get_user_session(&app_state, &cookie_jar).await;
    req.extensions_mut().insert(user_state.clone());

    let response = nxt.run(req).await;

    match user_state {
        UserState::ValidSession(_) => response,
        UserState::ExpiredToken => (
            cookie_jar.remove("token"),
            Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("Location", "/login")
                .body(Body::from("Session expired, please log in again."))
                .unwrap(),
        )
            .into_response(),
        UserState::InvalidToken => (cookie_jar.remove("token"), response).into_response(),
        UserState::NoToken => response,
    }
}

#[derive(Debug)]
pub enum WebError {
    DatabaseError,
    RenderError,
}

impl IntoResponse for WebError {
    fn into_response(self) -> axum::response::Response {
        match self {
            WebError::DatabaseError => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Database Error"))
                .unwrap(),
            WebError::RenderError => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Error rendering page"))
                .unwrap(),
        }
    }
}

#[axum::debug_handler]
pub async fn view_hw(
    app_state: State<Arc<AppState>>,
    Extension(user_state): Extension<UserState>,
) -> Result<Response<Body>, WebError> {
    dbg!(serde_json::to_string(&user_state).unwrap());

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(
            app_state
                .templates
                .render(
                    "home",
                    &json!({
                        "user": user_state,
                        "build": app_state.build_info
                    }),
                )
                .or(Err(WebError::RenderError))?,
        ))
        .or(Err(WebError::RenderError))
}

#[axum::debug_handler]
pub async fn view_posts(
    app_state: State<Arc<AppState>>,
    Extension(user_state): Extension<UserState>,
) -> Result<Response<Body>, WebError> {
    let mut categories: Vec<Category> = sqlx::query!("SELECT id, name FROM Categorys;")
        .fetch_all(&app_state.db_pool)
        .await
        .or(Err(WebError::DatabaseError))?
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
                .or(Err(WebError::DatabaseError))?)
    }

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(
            app_state
                .templates
                .render(
                    "post-list",
                    &json!({
                        "user": user_state,
                        "categories": categories,
                        "build": app_state.build_info
                    }),
                )
                .or(Err(WebError::RenderError))?,
        ))
        .or(Err(WebError::RenderError))
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct PageOpts {
    noheader: Option<bool>,
}

#[axum::debug_handler]
pub async fn view_post(
    app_state: State<Arc<AppState>>,
    Path(post_id): Path<Uuid>,
    Extension(user_state): Extension<UserState>,
    Query(page_opts): Query<PageOpts>,
) -> Result<Response<Body>, WebError> {
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
        .body(Body::from(
            app_state
                .templates
                .render(
                    "post-view",
                    &json!({
                        "user": user_state,
                        "post": post,
                        "page_opts": page_opts,
                        "build": app_state.build_info
                    }),
                )
                .or(Err(WebError::RenderError))?,
        ))
        .or(Err(WebError::RenderError))
}

#[axum::debug_handler]
pub async fn view_post_form(
    app_state: State<Arc<AppState>>,
    Extension(user_state): Extension<UserState>,
) -> Result<Response<Body>, WebError> {
    match &user_state {
        UserState::ValidSession(u) => u,
        _ => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("You must be logged in to post"))
                .or(Err(WebError::RenderError)?);
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
        .body(Body::from(
            app_state
                .templates
                .render(
                    "post-form",
                    &json!({
                        "user": user_state,
                        "categories": categories,
                        "build": app_state.build_info
                    }),
                )
                .or(Err(WebError::RenderError))?,
        ))
        .or(Err(WebError::RenderError))
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct NewPostForm {
    title: String,
    body: String,
    category: Uuid,
}

#[axum::debug_handler]
pub async fn new_post(
    app_state: State<Arc<AppState>>,
    Extension(user_state): Extension<UserState>,
    Form(form): Form<NewPostForm>,
) -> Result<Response<Body>, WebError> {
    let user = match &user_state {
        UserState::ValidSession(user) => user,
        _ => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("You must be logged in to post"))
                .or(Err(WebError::RenderError));
        }
    };

    dbg!("New Post: {title}, {body}");

    let query = sqlx::query!(
        "INSERT INTO Posts (title, body, user_id, category_id) VALUES ($1, $2, $3, $4) RETURNING id;",
        form.title,
        form.body,
        user.id,
        form.category
    ).fetch_one(&app_state.db_pool).await;

    match query {
        Ok(r) => Ok(Redirect::to(format!("/posts/{}", r.id).as_str()).into_response()),
        Err(e) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("{e}")))
            .or(Err(WebError::RenderError)),
    }
}

#[axum::debug_handler]
pub async fn signup_view(
    app_state: State<Arc<AppState>>,
    Extension(user_state): Extension<UserState>,
) -> Result<Response<Body>, WebError> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(
            app_state
                .templates
                .render(
                    "signup",
                    &json!({
                        "user": user_state,
                        "build": app_state.build_info
                    }),
                )
                .or(Err(WebError::RenderError))?,
        ))
        .or(Err(WebError::RenderError))
}

#[axum::debug_handler]
pub async fn signup_handler(
    app_state: State<Arc<AppState>>,
    cookie_jar: CookieJar,
    Extension(user_state): Extension<UserState>,
    form: Form<LoginFormData>,
) -> Result<Response<Body>, WebError> {
    // Check if user already exists
    if sqlx::query!("SELECT name FROM Users WHERE name = $1", &form.username)
        .fetch_optional(&app_state.db_pool)
        .await
        .unwrap()
        .is_some()
    {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(
                app_state
                    .templates
                    .render(
                        "signup",
                        &json!({
                            "user": user_state,
                            "err_msg": "User already exists",
                            "build": app_state.build_info
                        }),
                    )
                    .or(Err(WebError::RenderError))?,
            ))
            .or(Err(WebError::RenderError));
    }

    if let Err(e) = validate_username(&form.username) {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(
                app_state
                    .templates
                    .render(
                        "signup",
                        &json!({
                            "user": user_state,
                            "err_msg": format!("{e}"),
                            "build": app_state.build_info
                        }),
                    )
                    .or(Err(WebError::RenderError))?,
            ))
            .or(Err(WebError::RenderError));
    }

    if form.password.trim().is_empty() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(
                app_state
                    .templates
                    .render(
                        "signup",
                        &json!({
                            "user": user_state,
                            "err_msg": "Password cannot be empty",
                            "build": app_state.build_info
                        }),
                    )
                    .or(Err(WebError::RenderError))?,
            ))
            .or(Err(WebError::RenderError));
    }

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

    Ok((
        cookie_jar.add(Cookie::new("token", session_token.to_string())),
        Redirect::to("/"),
    )
        .into_response())
}

#[axum::debug_handler]
pub async fn login_view(
    app_state: State<Arc<AppState>>,
    Extension(user_state): Extension<UserState>,
) -> Result<Response<Body>, WebError> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(
            app_state
                .templates
                .render(
                    "login",
                    &json!({
                        "user": user_state,
                        "build": app_state.build_info
                    }),
                )
                .unwrap(),
        ))
        .or(Err(WebError::RenderError))
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct LoginFormData {
    username: String,
    password: String,
    invite: Option<String>,
}

#[axum::debug_handler]
pub async fn login_handler(
    app_state: State<Arc<AppState>>,
    Extension(user_state): Extension<UserState>,
    cookie_jar: CookieJar,
    form: Form<LoginFormData>,
) -> Result<Response<Body>, WebError> {
    let db_user = match sqlx::query!("SELECT * FROM Users WHERE name = $1;", &form.username,)
        .fetch_optional(&app_state.db_pool)
        .await
        .unwrap()
    {
        Some(e) => e,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from(
                    app_state
                        .templates
                        .render(
                            "login",
                            &json!({
                                "user": user_state,
                                "err_msg": "User not found", // Todo: Maybe don't announce this publicly
                                "build": app_state.build_info
                            }),
                        )
                        .or(Err(WebError::RenderError))?,
                ))
                .or(Err(WebError::RenderError));
        }
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
            .body(Body::from(
                app_state
                    .templates
                    .render(
                        "login",
                        &json!({
                            "user": user_state,
                            "err_msg": "Invalid Password",
                            "build": app_state.build_info
                        }), // Todo: Maybe don't announce this publicly
                    )
                    .or(Err(WebError::RenderError))?,
            ))
            .or(Err(WebError::RenderError));
    }

    let session_token = sqlx::query!(
        "INSERT INTO UserTokens (user_id) VALUES ($1) RETURNING token;",
        &db_user.id,
    )
    .fetch_one(&app_state.db_pool)
    .await
    .expect("Failed to insert user token")
    .token;

    Ok((
        cookie_jar.add(Cookie::new("token", session_token.to_string())),
        Redirect::to("/"),
    )
        .into_response())
}

#[axum::debug_handler]
pub async fn logout_handler(
    app_state: State<Arc<AppState>>,
    cookie_jar: CookieJar,
) -> Result<Response<Body>, WebError> {
    let token: Uuid = match cookie_jar.get("token") {
        Some(c) => Uuid::from_str(c.value_trimmed()).unwrap(),
        None => {
            return Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header("Location", "/")
                .body(Body::from(""))
                .or(Err(WebError::RenderError));
        }
    };

    let _query = sqlx::query!("DELETE FROM UserTokens WHERE token = $1", token)
        .fetch_optional(&app_state.db_pool)
        .await
        .unwrap();

    Ok((cookie_jar.remove("token"), Redirect::to("/")).into_response())
}
