use crate::{config::Config, db::Database, cache::authorization_code_cache::AuthorizationCodeCache};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub auth_code_cache: AuthorizationCodeCache,
}
