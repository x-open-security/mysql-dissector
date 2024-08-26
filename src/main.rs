use config::Config;
use network::Capture;
use packets::DBPacket;
use parser::executor::Executor;
use std::collections::HashMap;
use tokio::sync::mpsc;
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

    let (tx, rx) = mpsc::channel::<Vec<Box<dyn DBPacket>>>(32);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();



    // Clone conf for capture and executor
    let conf_capture = conf.clone();
    let conf_executor = conf.clone();

    // start async capture
    runtime.spawn(async move {
        let mut capture = Capture::new(conf_capture, tx);
        capture.active();
    });

    // start async pkt parser
    runtime.block_on(async move {
        let mut executor = Executor::new(conf_executor, rx);
        executor.run().await;
    });
}
