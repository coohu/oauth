use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct CachedAuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub user_id: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: i64,
}

#[derive(Clone)]
pub struct AuthorizationCodeCache {
    inner: Arc<RwLock<HashMap<String, CachedAuthorizationCode>>>,
}

impl AuthorizationCodeCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Insert a new authorization code into the cache
    pub async fn insert(&self, auth_code: CachedAuthorizationCode) {
        let mut cache = self.inner.write().await;
        cache.insert(auth_code.code.clone(), auth_code);
    }

    /// Get and remove an authorization code from the cache (mark as used)
    pub async fn get_and_remove(&self, code: &str) -> Option<CachedAuthorizationCode> {
        let now = chrono::Utc::now().timestamp();
        let mut cache = self.inner.write().await;
        
        let auth_code = cache.get(code)?;
        
        if auth_code.expires_at > now {
            cache.remove(code)
        } else {
            cache.remove(code);
            None
        }
    }

    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut cache = self.inner.write().await;
        cache.retain(|_, auth_code| auth_code.expires_at > now);
    }

    /// Load multiple codes into the cache
    pub async fn load_codes(&self, codes: Vec<CachedAuthorizationCode>) {
        let mut cache = self.inner.write().await;
        for code in codes {
            cache.insert(code.code.clone(), code);
        }
    }

    /// Get count of cached codes (for monitoring)
    #[allow(dead_code)]
    pub async fn len(&self) -> usize {
        let cache = self.inner.read().await;
        cache.len()
    }
}

impl Default for AuthorizationCodeCache {
    fn default() -> Self {
        Self::new()
    }
}
