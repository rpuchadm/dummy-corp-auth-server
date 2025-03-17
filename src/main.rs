use chrono::prelude::*;
use rocket::FromForm;
use rocket::form::Form;
use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{State, delete, get, launch, post, routes}; // put
use sqlx::{Decode, FromRow};

mod postgresini;
mod randomtoken;
mod sesion;

use sesion::{
    Session, postgres_get_session_by_code_client_id, postgres_get_session_by_codenull_token,
    postgres_insert_session, postgres_update_session_set_token_codenull_by_id,
    postgres_update_session_token_null_closed_at_by_id, redis_get_session_by_token,
    redis_set_session_by_token,
};

// declara string con token supersecreto que permite crear sesiones nuevas y desactivar viejas
const SUPER_SECRET: &str = "mysupersecret"; // en un futuro se sacará de ENV

const REDIS_SERVER: &str = "redis://:WEVDH12f34r56w78m9@127.0.0.1/";

struct AppState {
    pool: sqlx::Pool<sqlx::Postgres>,
}

struct BearerToken(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BearerToken {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        if let Some(auth_header) = request.headers().get_one("Authorization") {
            if auth_header.starts_with("Bearer ") {
                let token = auth_header[7..].to_string();
                return Outcome::Success(BearerToken(token));
            }
        }
        Outcome::Error((Status::Unauthorized, ()))
    }
}

#[derive(Deserialize, Serialize, FromForm)]
struct AccessTokenRequest {
    //grant_type: String,
    client_id: String,
    //client_secret: String,
    //redirect_uri: String,
    code: String,
}

// a post accessToken se accede 1 sola vez con el code para obtener el token
#[post("/accessToken", data = "<request>")]
async fn access_token(
    state: &State<AppState>,
    request: Form<AccessTokenRequest>,
) -> Result<Json<Session>, Status> {
    // procesar los datos del formulario
    //let grant_type = &request.grant_type;
    let client_id = &request.client_id;
    //let client_secret = &request.client_secret;
    //let redirect_uri = &request.redirect_uri;
    let code = &request.code;

    print!("access_token client_id: {}, code: {}", client_id, code);

    let pool = state.pool.clone();

    // Obtiene la sesión por el código de autorización y el id del cliente
    let mut session = postgres_get_session_by_code_client_id(&pool, code, client_id)
        .await
        .map_err(|err| {
            eprintln!(
                "Error getting session by code={} and client_id={} : {:?}",
                code, client_id, err
            );
            Status::Forbidden
        })?;

    // Log para inspeccionar la sesión
    println!("access_token Session: {:?}", session);

    let token = randomtoken::random_token(128);

    // Actualiza el código de autorización a nulo
    postgres_update_session_set_token_codenull_by_id(&pool, session.id, &token)
        .await
        .or_else(|err| {
            eprintln!(
                "Error updating session token and code to null by id={} : {:?}",
                session.id, err
            );
            Err(Status::InternalServerError)
        })
        .unwrap();

    session.token = Some(token);
    session.code = None;

    Ok(Json(session.clone()))
}

// a get profile se accede de manera reiterada con el token para obtener la sesión
#[get("/profile")]
async fn profile(state: &State<AppState>, token: BearerToken) -> Result<Json<Session>, Status> {
    let client = redis::Client::open(REDIS_SERVER).map_err(|err| {
        eprintln!("Error connecting to redis: {:?}", err);
        Status::InternalServerError
    })?;
    let session = redis_get_session_by_token(&client, &token.0)
        .await
        .map_err(|err| {
            eprintln!("Error getting session by token={} : {:?}", token.0, err);
            Status::InternalServerError
        })?;

    if let Some(session) = session {
        // println!("Session from redis: {:?}", session);
        return Ok(Json(session));
    }

    let pool = state.pool.clone();
    let mut session = postgres_get_session_by_codenull_token(&pool, &token.0)
        .await
        .map_err(|err| {
            eprintln!(
                "Error getting session by code null and token={} : {:?}",
                token.0, err
            );
            Status::Unauthorized
        })?;

    // println!("Session from postgres: {:?}", session);

    session.token = None;
    let client = redis::Client::open(REDIS_SERVER).map_err(|err| {
        eprintln!("Error connecting to redis: {:?}", err);
        Status::InternalServerError
    })?;
    redis_set_session_by_token(&client, &token.0, &session)
        .await
        .map_err(|err| {
            eprintln!(
                "Error setting session
        by token={} : {:?}",
                token.0, err
            );
            Status::InternalServerError
        })?;

    Ok(Json(session.clone()))
}

#[derive(Deserialize)]
struct NewSessionRequest {
    client_id: String,
    user_id: i32,
    expires_in_min: i64,
    attributes: serde_json::Value,
}

#[post("/session", data = "<session_request>")]
async fn new_session(
    state: &State<AppState>,
    session_request: Json<NewSessionRequest>,
    token: BearerToken,
) -> Result<Json<Session>, Status> {
    if token.0 != SUPER_SECRET {
        eprintln!("Error invalid super secret token");
        return Err(Status::Unauthorized);
    }

    let code = randomtoken::random_token(32);

    let pool = state.pool.clone();

    let expires_at: NaiveDateTime =
        (Utc::now() + chrono::Duration::minutes(session_request.expires_in_min)).naive_utc();

    postgres_insert_session(
        &pool,
        &code,
        &session_request.client_id,
        session_request.user_id,
        expires_at,
        session_request.attributes.clone(),
    )
    .await
    .or_else(|err| {
        eprintln!("Error inserting session : {:?}", err);
        Err(Status::InternalServerError)
    })?;

    let code_some: Option<String> = Some(code);
    let token_none: Option<String> = None;

    let session = Session {
        id: 0,
        client_id: session_request.client_id.clone(),
        code: code_some,
        token: token_none,
        user_id: session_request.user_id,
        created_at: chrono::Utc::now().naive_utc(),
        expires_at,
        attributes: session_request.attributes.clone(),
    };

    Ok(Json(session))
}

#[derive(Deserialize)]
struct DeleteSessionRequest {
    token: String,
}

#[delete("/session", data = "<session_request>")]
async fn delete_session(
    state: &State<AppState>,
    session_request: Json<DeleteSessionRequest>,
    token: BearerToken,
) -> Result<Status, Status> {
    if token.0 != SUPER_SECRET {
        eprintln!("Error invalid super secret token");
        return Err(Status::Unauthorized);
    }

    let pool = state.pool.clone();

    let session = postgres_get_session_by_codenull_token(&pool, &session_request.token)
        .await
        .map_err(|err| {
            eprintln!(
                "Error getting session by code null and token={} : {:?}",
                session_request.token, err
            );
            Status::Forbidden
        })?;

    postgres_update_session_token_null_closed_at_by_id(&pool, session.id)
        .await
        .or_else(|err| {
            eprintln!(
                "Error updating session token to null and closed_at to now by id={} : {:?}",
                session.id, err
            );
            Err(Status::InternalServerError)
        })?;

    Ok(Status::Ok)
}

#[launch]
async fn rocket() -> _ {
    let pool: sqlx::Pool<sqlx::Postgres> = sqlx::postgres::PgPool::connect(POSTGRES_SERVER)
        .await
        .or_else(|err| {
            eprintln!("Error connecting to the database: {:?}", err);
            Err(err)
        })
        .unwrap();

    // sacar de variables de entorno AUTH_SUPER_SECRET_TOKEN
    let auth_super_secret_token = std::env::var("AUTH_SUPER_SECRET_TOKEN").unwrap_or_default();
    if auth_super_secret_token.is_empty() {
        eprintln!("Error AUTH_SUPER_SECRET_TOKEN is empty");
        std::process::exit(1);
    }

    postgresini::initialization(pool.clone()).await;

    rocket::build().manage(AppState { pool }).mount(
        "/",
        routes![access_token, delete_session, new_session, profile],
    )
}

// constante con el servidor de postgres
const POSTGRES_SERVER: &str = "postgresql://myuser:mypassword@localhost:5432/mydatabase";
