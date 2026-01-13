use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct CachedAccessToken {
    pub user_id: String,
    pub expires_at: i64,
}

#[derive(Clone)]
pub struct TokenCache {
    /// Access token cache: token_hash -> CachedAccessToken
    access_tokens: Arc<RwLock<HashMap<String, CachedAccessToken>>>,
}

impl TokenCache {
    pub fn new() -> Self {
        Self {
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert_access_token(&self, token_hash: String, user_id: String, expires_at: i64) {
        let mut cache = self.access_tokens.write().await;
        cache.insert(
            token_hash,
            CachedAccessToken {user_id, expires_at},
        );
    }

    pub async fn get_user_id_by_access_token(&self, token_hash: &str) -> Option<String> {
        let now = chrono::Utc::now().timestamp();
        let cache = self.access_tokens.read().await;
        
        cache.get(token_hash).and_then(|token| {
            if token.expires_at > now {
                Some(token.user_id.clone())
            } else {
                None
            }
        })
    }

    #[allow(dead_code)]
    pub async fn remove_access_token(&self, token_hash: &str) {
        let mut cache = self.access_tokens.write().await;
        cache.remove(token_hash);
    }

    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut cache = self.access_tokens.write().await;
        cache.retain(|_, token| token.expires_at > now);
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}
