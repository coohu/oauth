use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use fastbloom::BloomFilter;

#[derive(Clone)]
pub struct CachedAccessToken {
    pub user_id: Option<String>,
    pub expires_at: i64,
}

#[derive(Clone)]
pub struct TokenCache {
    /// Access token cache: token_hash -> CachedAccessToken
    access_tokens: Arc<RwLock<HashMap<String, CachedAccessToken>>>,
    bloom: Arc<RwLock<BloomFilter>>,
}

impl TokenCache {
    pub fn new() -> Self {
        // Initialize bloom filter with capacity for 100000 items and 0.01 false positive rate
        let bloom = BloomFilter::with_false_pos(0.01).expected_items(100000);
        Self {
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
            bloom: Arc::new(RwLock::new(bloom)),
        }
    }

    pub async fn insert_access_token(&self, token_hash: String, user_id: Option<String>, expires_at: i64) {
        let mut bloom = self.bloom.write().await;
        bloom.insert(token_hash.as_bytes());
        drop(bloom);
        
        let mut cache = self.access_tokens.write().await;
        cache.insert(
            token_hash,
            CachedAccessToken {user_id, expires_at},
        );
    }

    pub async fn load_tokens(&self, tokens: Vec<(String, CachedAccessToken)>) {
        let mut bloom = self.bloom.write().await;
        let mut cache = self.access_tokens.write().await;
        
        for (hash, token) in tokens {
            bloom.insert(hash.as_bytes());
            cache.insert(hash, token);
        }
    }

    pub async fn get_user_id_by_access_token(&self, token_hash: &str) -> Option<String> {
        // Check bloom filter first to avoid unnecessary HashMap lookups
        let bloom = self.bloom.read().await;
        if !bloom.contains(token_hash.as_bytes()) {
            return None;
        }
        drop(bloom);
        
        let now = chrono::Utc::now().timestamp();
        let cache = self.access_tokens.read().await;
        
        cache.get(token_hash).and_then(|token| {
            if token.expires_at > now {
                token.user_id.clone()
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
