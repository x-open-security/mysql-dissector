use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Config {
    pub bpf: String,
    pub device: String,
    pub support_db: HashMap<String, String>,
}