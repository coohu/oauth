use sha2::{Digest, Sha256};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Verify PKCE code_verifier against code_challenge
/// Supports both S256 (SHA256) and plain methods
pub fn verify_pkce(
    code_verifier: &str,
    code_challenge: &str,
    code_challenge_method: &str,
) -> bool {
    match code_challenge_method {
        "S256" => {
            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let result = hasher.finalize();
            let computed_challenge = URL_SAFE_NO_PAD.encode(result);
            computed_challenge == code_challenge
        }
        "plain" => code_verifier == code_challenge,
        _ => false,
    }
}

pub fn generate_secure_token(length: usize) -> String {
    use rand::Rng;
    let bytes: Vec<u8> = (0..length)
        .map(|_| rand::thread_rng().gen::<u8>())
        .collect();
    URL_SAFE_NO_PAD.encode(bytes)
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

pub fn is_valid_email(email: &str) -> bool {
    // A very simple email validation without regex crate
    if email.len() < 5 {
        return false;
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let domain_parts: Vec<&str> = parts[1].split('.').collect();
    domain_parts.len() >= 2 && !domain_parts.iter().any(|s| s.is_empty()) && !parts[0].is_empty()
}
