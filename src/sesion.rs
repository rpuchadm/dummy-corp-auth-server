use chrono::{NaiveDateTime, Utc};
use redis::AsyncCommands;
use rocket::{
    http::Status,
    serde::{Deserialize, Serialize},
};
use sqlx::{Decode, FromRow};

use crate::{EXPIRES_IN_SECONDS, randomtoken};

#[derive(Serialize, Deserialize, Clone, FromRow, Decode, Debug)]
pub struct Session {
    pub id: i32,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub user_id: Option<i32>,
    pub redirect_uri: String,
    pub created_at: chrono::NaiveDateTime,
    pub expires_at: chrono::NaiveDateTime,
    pub attributes: serde_json::Value,
}

pub async fn postgres_insert_session(
    pool: &sqlx::Pool<sqlx::Postgres>,
    client_id: &str,
    user_id: Option<i32>, // Cambiado a Option<i32>
    code: &str,
    token: &str,
    redirect_uri: &str,
    expires_in_min: chrono::NaiveDateTime,
    attributes: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO sessions (
            client_id, user_id,
            code, token,
            redirect_uri,
            expires_at, attributes
        ) VALUES (
            $1, $2,
            $3, $4,
            $5,
            $6, $7
        )
        "#,
    )
    .bind(client_id)
    .bind(user_id) // sqlx maneja automáticamente el Option
    .bind(code)
    .bind(token)
    .bind(redirect_uri)
    .bind(expires_in_min)
    .bind(attributes)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn postgres_get_session_by_codenull_token(
    pool: &sqlx::Pool<sqlx::Postgres>,
    token: &str,
) -> Result<Session, sqlx::Error> {
    let session = sqlx::query_as::<_, Session>(
        r#"
        SELECT
            id, client_id, code, token, user_id, 
            redirect_uri,
            created_at, expires_at, attributes
        FROM sessions
        WHERE  token = $1
        and expires_at > now()
        "#, // ( code is NULL or code == '' ) and
    )
    .bind(token)
    .fetch_one(pool)
    .await?;

    Ok(session)
}

pub async fn postgres_get_session_by_code_client_id(
    pool: &sqlx::Pool<sqlx::Postgres>,
    code: &str,
    client_id: &str,
) -> Result<Session, sqlx::Error> {
    let session = sqlx::query_as::<_, Session>(
        r#"
        SELECT
            id, client_id, code, token, user_id, 
            redirect_uri,
            created_at, expires_at, attributes
        FROM sessions
        WHERE code = $1 and client_id = $2
        and expires_at > now()
        "#,
    )
    .bind(code)
    .bind(client_id)
    .fetch_one(pool)
    .await?;

    Ok(session)
}

pub async fn postgres_update_session_set_token_codenull_by_id(
    pool: &sqlx::Pool<sqlx::Postgres>,
    id: i32,
    token: &str,
) -> Result<(), sqlx::Error> {
    println!(
        "postgres_update_session_set_token_codenull_by_id: id: {}, token: {}",
        id, token
    );

    sqlx::query(
        r#"
        UPDATE sessions
        SET token = $1, code = NULL
        WHERE id = $2
        "#,
    )
    .bind(token)
    .bind(id)
    .execute(pool)
    .await?;

    // let result =
    /*let rows_affected = result.rows_affected();
    println!(
        "postgres_update_session_set_token_codenull_by_id - rows_affected {}",
        rows_affected
    );*/

    Ok(())
}

pub async fn postgres_update_session_token_null_closed_at_by_id(
    pool: &sqlx::Pool<sqlx::Postgres>,
    id: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE sessions
        SET token = null, closed_at = now()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

const SESSION_TOKEN_KEY: &str = "session-token:";
pub async fn redis_get_session_by_token(
    client: &redis::Client,
    token: &str,
) -> redis::RedisResult<Option<Session>> {
    let key = format!("{}:{}", SESSION_TOKEN_KEY, token);

    let mut con = client.get_multiplexed_async_connection().await.unwrap();
    let session_json: Option<String> = con.get(&key).await?;
    let session: Option<Session> = match session_json {
        Some(session_json) => Some(serde_json::from_str(&session_json).unwrap()),
        None => None,
    };
    Ok(session)
}
pub async fn redis_set_session_by_token(
    client: &redis::Client,
    token: &str,
    session: &Session,
    auth_redis_ttl: i64,
) -> redis::RedisResult<()> {
    let key = format!("{}:{}", SESSION_TOKEN_KEY, token);
    let mut con = client.get_multiplexed_async_connection().await.unwrap();
    let session_json = serde_json::to_string(session).unwrap();
    let _: () = con.set(&key, session_json).await?;
    let _: () = con.expire(&key, auth_redis_ttl).await?;
    Ok(())
}
/*
CREATE TABLE IF NOT EXISTS auth_clients (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    client_url VARCHAR(255) NOT NULL,
    client_url_callback VARCHAR(255),
    client_secret VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
); */

#[derive(FromRow)]
pub struct AuthClient {
    pub client_secret: Option<String>,
}

pub async fn postgres_select_auth_client_by_client_id(
    pool: &sqlx::Pool<sqlx::Postgres>,
    client_id: &str,
) -> Result<AuthClient, sqlx::Error> {
    let auth_client = sqlx::query_as::<_, AuthClient>(
        r#"
        SELECT
            client_secret
        FROM auth_clients
        WHERE client_id = $1
        "#,
    )
    .bind(client_id)
    .fetch_one(pool)
    .await?;

    Ok(auth_client)
}

pub async fn validate_authorization_code_usuarios(
    pool: &sqlx::Pool<sqlx::Postgres>,
    client_id: &str,
    //client_secret: &str,
    redirect_uri: &str,
    code: &str,
) -> Result<String, ()> {
    // Validar el código de autorización y las credenciales del cliente
    //let client = postgres_select_auth_client_by_client_id(pool, client_id)
    //    .await
    //    .map_err(|_| ())?;

    //if client.client_secret != Some(client_secret.to_string()) {
    //    return Err(());
    //}

    let session = postgres_get_session_by_code_client_id(pool, code, client_id)
        .await
        .map_err(|_| ())?;

    // si el token no es nulo y es diferente de vacío
    if session.token.is_some() {
        let token = session.token.unwrap();
        if !token.is_empty() && token != "" {
            eprintln!("Error invalid token not null {}", token);
            return Err(());
        }
    }

    if session.expires_at < Utc::now().naive_utc() {
        eprintln!("Error expired code");
        return Err(());
    }

    if session.redirect_uri != *redirect_uri {
        eprintln!("Error invalid redirect_uri");
        println!("session.redirect_uri: {}", session.redirect_uri);
        println!("redirect_uri: {}", redirect_uri);
        return Err(());
    }

    let access_token = randomtoken::random_token(128);

    // Actualiza el código de autorización a nulo
    postgres_update_session_set_token_codenull_by_id(&pool, session.id, &access_token)
        .await
        .or_else(|err| {
            eprintln!(
                "Error updating session token and code to null by id={} : {:?}",
                session.id, err
            );
            Err(Status::InternalServerError)
        })
        .unwrap();

    // calcula expires_in a partir de session.expires_at
    //let expires_in = session.expires_at.and_utc().timestamp() - Utc::now().timestamp();

    Ok(access_token)
}

pub async fn validate_client_credentials_aplicaciones(
    pool: &sqlx::Pool<sqlx::Postgres>,
    client_id: &str,
    client_secret: &str,
) -> Result<String, ()> {
    // Validar las credenciales del cliente
    let client = postgres_select_auth_client_by_client_id(pool, client_id)
        .await
        .map_err(|_| ())?;

    if client.client_secret.is_none() {
        eprint!("Error undefined client.client_secret");
        return Err(());
    }

    if client.client_secret != Some(client_secret.to_string()) {
        eprint!("Error invalid client_secret");
        return Err(());
    }

    let expires_at: NaiveDateTime =
        (Utc::now() + chrono::Duration::seconds(EXPIRES_IN_SECONDS)).naive_utc();

    let attributes = serde_json::Value::Null;

    let access_token = randomtoken::random_token(128);

    postgres_insert_session(
        &pool,
        client_id,
        None,
        "",
        &access_token,
        "",
        expires_at,
        attributes,
    )
    .await
    .or_else(|err| {
        eprintln!("Error inserting session: {:?}", err);
        Err(Status::InternalServerError)
    })
    .unwrap();

    Ok(access_token)
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
