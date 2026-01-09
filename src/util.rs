use sha2::{Digest, Sha256};

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

pub async fn verify_turnstile(
    secret_key: &str,
    token: &str,
    remote_ip: Option<&str>,
) -> Result<bool, reqwest::Error> {
    #[derive(serde::Deserialize)]
    struct TurnstileResponse {
        success: bool,
    }

    let client = reqwest::Client::new();
    let mut params = std::collections::HashMap::new();
    params.insert("secret", secret_key);
    params.insert("response", token);
    if let Some(ip) = remote_ip {
        params.insert("remoteip", ip);
    }

    let res = client
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&params)
        .send()
        .await?
        .json::<TurnstileResponse>()
        .await?;

    Ok(res.success)
}
