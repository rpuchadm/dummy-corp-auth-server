pub async fn initialization(pool: sqlx::Pool<sqlx::Postgres>) {
    sqlx::query(
        r#"        
        DROP INDEX IF EXISTS idx_sessions_code_client_id;
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        DROP INDEX IF EXISTS idx_sessions_token;
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"        
        DROP TABLE IF EXISTS sessions;
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            client_id TEXT NOT NULL,
            code TEXT,
            token TEXT,
            user_id INTEGER,
            redirect_uri TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            closed_at TIMESTAMP,
            attributes JSONB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES persons(id),
            FOREIGN KEY (client_id) REFERENCES auth_clients(client_id)	
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    // Crea un índice para que code y client_id sean únicos cuando code no sea null
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_sessions_code_client_id
        ON sessions (code, client_id)
        WHERE code IS NOT NULL
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    // Crea un índice para que token sea único cuando no sea null
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_sessions_token
        ON sessions (token)
        WHERE token IS NOT NULL
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();
}
