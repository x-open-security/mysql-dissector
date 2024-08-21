use config::Config;
use network::Capture;
use std::collections::HashMap;
fn main() {
    env_logger::init();
    let mut db = HashMap::new();
    db.insert("3309".to_string(), "mysql".to_string());
    let conf = Config {
        // storage: &config::STORAGE,
        bpf: "tcp and port 3309".to_string(),
        device: "en0".to_string(),
        support_db: db,
    };
    Capture::new(conf).active();
}
