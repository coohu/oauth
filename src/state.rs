use crate::{
    cache::{
        authorization_code_cache::AuthorizationCodeCache,
        token_cache::TokenCache,
    },
    config::Config,
    db::Database,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub auth_code_cache: AuthorizationCodeCache,
    pub token_cache: TokenCache,
}
