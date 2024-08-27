use config::Config;
use tokio::sync::mpsc;
use log::info;
use packets::{DBPacket, DBType};
use packets::mysql::{MySQLPacketRequest, MySQLPacketResponse};

pub struct Executor {
    pub config: Config,
    rx: mpsc::UnboundedReceiver<Vec<Box<dyn DBPacket>>>,
}

impl Executor {
    pub fn new(conf: Config, rx: mpsc::UnboundedReceiver<Vec<Box<dyn DBPacket>>>) -> Executor {
        Executor { config: conf , rx}
    }
    pub async fn run(&mut self) {
        loop {
            match self.rx.recv().await {
                None => {
                    panic!("Executor: Channel closed");
                }
                Some(packets) => {
                    for (index, pkt) in packets.iter().enumerate() {
                        let db_type = pkt.db_type();
                        match db_type {
                            DBType::MySQL => {
                                // do something
                                // packets -> mysql
                                if pkt.is_request() {
                                    let mysql_pkt = pkt.as_any().downcast_ref::<MySQLPacketRequest>().unwrap();
                                    info!("rx: MySQL Packet, index: {:?}, pkt:{:?}", index, mysql_pkt);
                                } else {
                                    let mysql_pkt = pkt.as_any().downcast_ref::<MySQLPacketResponse>().unwrap();
                                    info!("rx: MySQL Packet, index: {:?}, pkt:{:?}", index, mysql_pkt);
                                }
                            }
                            DBType::Unknown => {

                            }
                        }
                    }
                }
            }
        }
    }
}