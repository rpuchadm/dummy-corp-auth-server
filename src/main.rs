use base64::Engine; // Para decodificar la cadena Base64
use base64::engine::general_purpose; // Motor de Base64

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
    Session, postgres_get_session_by_codenull_token, postgres_insert_session,
    postgres_update_session_token_null_closed_at_by_id, redis_get_session_by_token,
    redis_set_session_by_token, validate_authorization_code_usuarios,
    validate_client_credentials_aplicaciones,
};

struct AppState {
    pool: sqlx::Pool<sqlx::Postgres>,
    auth_super_secret_token: String,
    redis_connection_string: String,
    auth_redis_ttl: i64,
}

#[derive(Debug)]
struct BasicAuth {
    username: String,
    password: String,
}
#[derive(Debug)]
struct BearerToken(String);
#[derive(Debug)]
struct BearerOrBasicAuth {
    bearer: Option<BearerToken>,
    basic: Option<BasicAuth>,
}
#[rocket::async_trait]
impl<'r> FromRequest<'r> for BearerOrBasicAuth {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let mut bearer = None;
        let mut basic = None;

        // Intentar extraer el token Bearer o las credenciales Basic Auth
        if let Some(auth_header) = request.headers().get_one("Authorization") {
            if auth_header.starts_with("Bearer ") {
                println!(
                    "BearerOrBasicAuth Authorization Bearer header: {}",
                    auth_header
                );
                let token = auth_header[7..].to_string();
                bearer = Some(BearerToken(token));
            } else if auth_header.starts_with("Basic ") {
                println!(
                    "BearerOrBasicAuth Authorization Basic header: {}",
                    auth_header
                );
                // Intentar extraer las credenciales Basic Auth
                let encoded = &auth_header[6..];
                if let Ok(decoded) = general_purpose::STANDARD.decode(encoded) {
                    if let Ok(credentials) = String::from_utf8(decoded) {
                        let parts: Vec<&str> = credentials.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            let username = parts[0].to_string();
                            let password = parts[1].to_string();
                            basic = Some(BasicAuth { username, password });
                        }
                    }
                }
            }
        } else {
            println!("BearerOrBasicAuth No Authorization header");
        }

        // Siempre devolver éxito, incluso si no se encontró autenticación
        Outcome::Success(BearerOrBasicAuth { bearer, basic })
    }
}

#[derive(Deserialize, Serialize, FromForm)]
struct AccessTokenRequest {
    grant_type: String,
    client_id: Option<String>,
    //client_secret: Option<String>,
    redirect_uri: Option<String>,
    code: Option<String>,
    //refresh_token: Option<String>,
}

#[derive(Serialize)]
struct AccessTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
}

// a post accessToken se accede 1 sola vez con el code para obtener el token
#[post("/accessToken", data = "<request>")]
async fn access_token(
    state: &State<AppState>,
    bobauth: BearerOrBasicAuth,
    request: Form<AccessTokenRequest>,
) -> Result<Json<AccessTokenResponse>, Status> {
    // procesar los datos del formulario
    let grant_type = &request.grant_type;

    println!("accessToken grant_type: {:?}", grant_type);

    let pool = state.pool.clone();

    match grant_type.as_str() {
        // Flujo de Authorization Code (para usuarios)
        "authorization_code" => {
            let client_id = request.client_id.as_ref().ok_or(Status::BadRequest)?;
            //let client_secret = request.client_secret.as_ref().ok_or(Status::BadRequest)?;
            let redirect_uri = request.redirect_uri.as_ref().ok_or(Status::BadRequest)?;
            let code = request.code.as_ref().ok_or(Status::BadRequest)?;

            // Validar el código de autorización y las credenciales del cliente
            let access_token = validate_authorization_code_usuarios(
                &pool,
                client_id,
                //client_secret,
                redirect_uri,
                code,
            )
            .await
            .map_err(|_| Status::Unauthorized)?;

            Ok(Json(AccessTokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: EXPIRES_IN_SECONDS, // Tiempo de expiración en segundos
            }))
        }

        // Flujo de Client Credentials (para aplicaciones)
        "client_credentials" => {
            let auth = bobauth.basic.ok_or(Status::BadRequest)?;
            let client_id = auth.username;
            let client_secret = auth.password;

            // Validar las credenciales del cliente
            let access_token =
                validate_client_credentials_aplicaciones(&pool, &client_id, &client_secret)
                    .await
                    .map_err(|_| Status::Unauthorized)?;

            Ok(Json(AccessTokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: EXPIRES_IN_SECONDS, // Tiempo de expiración en segundos
            }))
        }

        _ => Err(Status::BadRequest),
    }
}

// a get profile se accede de manera reiterada con el token para obtener la sesión
#[get("/profile")]
async fn profile(
    state: &State<AppState>,
    bobauth: BearerOrBasicAuth,
) -> Result<Json<Session>, Status> {
    let client = redis::Client::open(state.redis_connection_string.clone()).map_err(|err| {
        eprintln!("Error connecting to redis: {:?}", err);
        Status::InternalServerError
    })?;

    let token = bobauth
        .bearer
        .ok_or(Status::Unauthorized)
        .map_err(|_| Status::Unauthorized)?;

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
    redis_set_session_by_token(&client, &token.0, &session, state.auth_redis_ttl)
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
    redirect_uri: String,
    expires_in_min: i64,
    attributes: serde_json::Value,
}

// TODO arreglar expires: EXPIRES_IN_SECONDS vs expires_in_min
const EXPIRES_IN_SECONDS: i64 = 3600;

#[post("/session", data = "<session_request>")]
async fn new_session(
    state: &State<AppState>,
    session_request: Json<NewSessionRequest>,
    bobauth: BearerOrBasicAuth,
) -> Result<Json<Session>, Status> {
    let token = bobauth
        .bearer
        .ok_or(Status::Unauthorized)
        .map_err(|_| Status::Unauthorized)?;

    if token.0 != state.auth_super_secret_token {
        eprintln!("Error invalid auth super secret token");
        return Err(Status::Unauthorized);
    }

    let code = randomtoken::random_token(32);

    let pool = state.pool.clone();

    let expires_at: NaiveDateTime =
        (Utc::now() + chrono::Duration::minutes(session_request.expires_in_min)).naive_utc();

    postgres_insert_session(
        &pool,
        &session_request.client_id,
        session_request.user_id,
        &code,
        "",
        &session_request.redirect_uri,
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
        redirect_uri: session_request.redirect_uri.clone(),
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
    bobauth: BearerOrBasicAuth,
) -> Result<Status, Status> {
    let token = bobauth
        .bearer
        .ok_or(Status::Unauthorized)
        .map_err(|_| Status::Unauthorized)?;
    if token.0 != state.auth_super_secret_token {
        eprintln!("Error invalid auth super secret token");
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
    let auth_super_secret_token = std::env::var("AUTH_SUPER_SECRET_TOKEN").unwrap_or_default();
    if auth_super_secret_token.is_empty() {
        eprintln!("Error AUTH_SUPER_SECRET_TOKEN is empty");
        std::process::exit(1);
    }

    let redis_password = std::env::var("REDIS_PASSWORD").unwrap_or_default();
    let redis_host = std::env::var("REDIS_SERVICE").unwrap_or_default();
    let redis_port = std::env::var("REDIS_PORT").unwrap_or_default();

    if redis_password.is_empty() || redis_host.is_empty() || redis_port.is_empty() {
        eprintln!("Error REDIS_PASSWORD, REDIS_SERVICE or REDIS_PORT is empty");
        std::process::exit(1);
    }

    let redis_connection_string =
        format!("redis://:{}@{}:{}/", redis_password, redis_host, redis_port);

    //print!("redis_connection_string: {}\n", redis_connection_string);

    let auth_redis_ttl = std::env::var("AUTH_REDIS_TTL")
        .unwrap_or_else(|_| "120".to_string())
        .parse::<i64>()
        .expect("AUTH_REDIS_TTL must be a number");

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

    postgresini::initialization(pool.clone()).await;

    let cors = cors_options().to_cors().expect("Error al configurar CORS");

    rocket::build()
        .manage(AppState {
            pool,
            auth_super_secret_token,
            redis_connection_string,
            auth_redis_ttl,
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

/// Decodifica el encabezado de autorización Basic Auth
fn decode_basic_auth(auth_header: &str) -> Result<(String, String), Status> {
    let encoded = auth_header.trim_start_matches("Basic ");
    let decoded = base64::decode(encoded).map_err(|_| Status::BadRequest)?;
    let credentials = String::from_utf8(decoded).map_err(|_| Status::BadRequest)?;
    let mut parts = credentials.splitn(2, ':');
    let client_id = parts.next().ok_or(Status::BadRequest)?.to_string();
    let client_secret = parts.next().ok_or(Status::BadRequest)?.to_string();
    Ok((client_id, client_secret))
}
