use sqlx::AnyPool;

pub async fn check_rate_limit(
    pool: &AnyPool,
    key: &str,
    limit: i64,
    window_secs: i64,
) -> Result<bool, sqlx::Error> {
    let now = chrono::Utc::now().timestamp();
    let window_start = now - window_secs;

    // Clean up old entries occasionally or just filter them out
    // For simplicity, we'll just update the existing entry
    
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT count, last_seen FROM rate_limits WHERE key = ?"
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((count, last_seen)) => {
            if last_seen < window_start {
                // Reset window
                sqlx::query("UPDATE rate_limits SET count = 1, last_seen = ? WHERE key = ?")
                    .bind(now)
                    .bind(key)
                    .execute(pool)
                    .await?;
                Ok(true)
            } else if count < limit {
                // Increment count
                sqlx::query("UPDATE rate_limits SET count = count + 1, last_seen = ? WHERE key = ?")
                    .bind(now)
                    .bind(key)
                    .execute(pool)
                    .await?;
                Ok(true)
            } else {
                // Limit exceeded
                Ok(false)
            }
        }
        None => {
            // New entry
            sqlx::query("INSERT INTO rate_limits (key, count, last_seen) VALUES (?, 1, ?)")
                .bind(key)
                .bind(now)
                .execute(pool)
                .await?;
            Ok(true)
        }
    }
}
#[allow(dead_code)]
pub async fn reset_rate_limit(
    pool: &AnyPool,
    key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM rate_limits WHERE key = ?")
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}
