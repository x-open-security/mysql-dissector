use config::Config;
use log::{error, info, warn};
use tokio::runtime::Runtime;
use network::session_manager::SessionManager;
use network::SessionPacket;
use packets::DBPacket;
use tokio::sync::mpsc;

pub struct Consumer {
    config: Config,
    raw_pkt_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    db_pkt_tx: mpsc::UnboundedSender<SessionPacket>,
}

impl Consumer {
    pub fn new(conf: Config, runtime: &Runtime, raw_pkt_rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Consumer {
        let (db_pkt_tx, db_pkt_rx) = mpsc::unbounded_channel::<SessionPacket>();
        let mut sm = SessionManager::new(conf.clone(), db_pkt_rx);
        if !sm.is_running() {
            runtime.spawn(async move {
                sm.run().await;
            });
        }
        Consumer {
            config: conf.clone(),
            raw_pkt_rx,
            db_pkt_tx,
        }
    }

    pub async fn run(&mut self) {
        loop {
            match self.raw_pkt_rx.recv().await {
                None => {
                    error!("Executor channel closed");
                }
                Some(raw_pkt) => {
                    // parse packet
                    let conf = &self.config;
                    match SessionPacket::new(conf, raw_pkt) {
                        Some(pkt) => {
                            match self.db_pkt_tx.send(pkt) {
                                Ok(_) => {
                                    // debug!("Send packet to session manager, payload len: {}", pkt.len());
                                }
                                Err(e) => {
                                    error!("Error happened: {}", e);
                                }
                            }
                        }
                        None => {
                           // nothing to do
                        }
                    };
                }
            }
        }
    }
}
