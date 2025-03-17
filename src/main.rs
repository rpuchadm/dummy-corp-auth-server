use chrono::prelude::*;
use rocket::form::Form;
use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};
use rocket::response::status::NotFound;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{FromForm, catchers};
use rocket::{State, catch, delete, get, launch, post, routes};
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};

mod postgresini;
mod randomtoken;
mod sesion;

use sesion::{
    Session, postgres_get_session_by_code_client_id, postgres_get_session_by_codenull_token,
    postgres_insert_session, postgres_update_session_set_token_codenull_by_id,
    postgres_update_session_token_null_closed_at_by_id, redis_get_session_by_token,
    redis_set_session_by_token,
};

struct AppState {
    pool: sqlx::Pool<sqlx::Postgres>,
    super_secret_token: String,
    redis_connection_string: String,
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
    let client = redis::Client::open(state.redis_connection_string.clone()).map_err(|err| {
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
    let client = redis::Client::open(state.redis_connection_string.clone()).map_err(|err| {
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
    if token.0 != state.super_secret_token {
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
    if token.0 != state.super_secret_token {
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
    let super_secret_token = std::env::var("AUTH_SUPER_SECRET_TOKEN").unwrap_or_default();
    if super_secret_token.is_empty() {
        eprintln!("Error AUTH_SUPER_SECRET_TOKEN is empty");
        std::process::exit(1);
    }

    let redis_password = std::env::var("REDIS_PASSWORD").unwrap_or_default();
    let redis_host = std::env::var("REDIS_SERVICE").unwrap_or_default();
    let redis_port = std::env::var("REDIS_PORT").unwrap_or_default();
    let redis_connection_string =
        format!("redis://:{}@{}:{}/", redis_password, redis_host, redis_port);

    let postgres_db = std::env::var("POSTGRES_DB").unwrap_or_default();
    let postgres_user = std::env::var("POSTGRES_USER").unwrap_or_default();
    let postgres_password = std::env::var("POSTGRES_PASSWORD").unwrap_or_default();
    let postgres_host = std::env::var("POSTGRES_SERVICE").unwrap_or_default();

    if postgres_db.is_empty()
        || postgres_user.is_empty()
        || postgres_password.is_empty()
        || postgres_host.is_empty()
    {
        eprintln!(
            "Error POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD or POSTGRES_SERVICE is empty"
        );
        std::process::exit(1);
    }

    let postgres_connexion_string = format!(
        "postgres://{}:{}@{}/{}",
        postgres_user, postgres_password, postgres_host, postgres_db
    );

    let pool: sqlx::Pool<sqlx::Postgres> =
        sqlx::postgres::PgPool::connect(postgres_connexion_string.as_str())
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

    let cors = cors_options().to_cors().expect("Error al configurar CORS");

    rocket::build()
        .manage(AppState {
            pool,
            super_secret_token,
            redis_connection_string,
        })
        .mount(
            "/",
            routes![access_token, delete_session, new_session, profile, healthz],
        )
        .register("/", catchers![not_found])
        .attach(cors)
}

#[get("/healthz")]
async fn healthz() -> &'static str {
    "OK"
}

fn cors_options() -> CorsOptions {
    let allowed_origins = AllowedOrigins::some_exact(&["http://localhost:5173/"]);

    // You can also deserialize this
    rocket_cors::CorsOptions {
        allowed_origins,
        allowed_methods: vec![
            rocket::http::Method::Delete,
            rocket::http::Method::Get,
            rocket::http::Method::Post,
            rocket::http::Method::Put,
            rocket::http::Method::Options,
        ]
        .into_iter()
        .map(From::from)
        .collect(),
        allowed_headers: AllowedHeaders::some(&["Authorization", "Accept", "Content-Type"]),
        allow_credentials: true,
        ..Default::default()
    }
}

#[catch(404)]
fn not_found(req: &Request) -> NotFound<String> {
    // Registrar el error 404 en los logs
    eprintln!("Ruta no encontrada: {}", req.uri());

    // Devolver una respuesta 404 personalizada
    NotFound(format!("Lo siento, la ruta '{}' no existe.", req.uri()))
}
