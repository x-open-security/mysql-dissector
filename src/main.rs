mod capture;
mod consumer;

use config::Config;
use log::info;
use capture::Capture;
use consumer::Consumer;

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

    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();

    let conf_capture = conf.clone();
    runtime.spawn(async {
        info!("Capture started with config: {:?}", conf_capture.clone());
        let mut capture = Capture::new(conf_capture, tx);
        capture.active().await;
    });

    let conf_executor = conf.clone();
    runtime.block_on(async {
        info!("Executor started with config: {:?}", conf_executor);
        let mut consumer = Consumer::new(conf_executor, &runtime, rx);
        consumer.run().await;
    });
}
