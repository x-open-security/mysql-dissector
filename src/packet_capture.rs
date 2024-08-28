use config::Config;
use log::{debug, error};

use pnet::datalink::Channel::Ethernet;
use tokio::sync::mpsc;
pub struct Capture {
    config: Config,
    raw_pkt_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl Capture {
    pub fn new(config: Config, raw_pkt_tx: mpsc::UnboundedSender<Vec<u8>>) -> Capture {
        Capture { config, raw_pkt_tx }
    }

    pub async fn active(&mut self) {
        let conf = &self.config;
        let ifaces = pnet::datalink::interfaces();
        let cap_iface = ifaces
            .iter()
            .find(|iface| iface.name == conf.device)
            .unwrap();

        let (_, mut rx) = match pnet::datalink::channel(&cap_iface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => {
                error!("Error happened: {}", e);
                return;
            }
        };

        loop {
            match rx.next() {
                Ok(packet) => match self.raw_pkt_tx.send(packet.to_vec()) {
                    Ok(_) => {
                        debug!("Send packet to executor, payload len: {}", packet.len());
                    }
                    Err(e) => {
                        error!("Error happened: {}", e);
                    }
                },
                Err(e) => {
                    error!("Error happened: {}", e);
                }
            }
        }
    }
}
