// HTTP client wiring: tokens flow in from configuration at runtime.
#[derive(Clone)]
pub struct ClientConfig {
    pub api_key_env: String,
    pub base_url: String,
    pub user_agent: String,
}

impl ClientConfig {
    pub fn from_env() -> Self {
        Self {
            api_key_env: "SERVICE_API_KEY".to_string(),
            base_url: "https://api.internal.example.com/v2".to_string(),
            user_agent: "deploy-bot/1.0".to_string(),
        }
    }
}
