use std::ops::Deref;
use config::Config;
use tokio::sync::mpsc;
use log::info;
use packets::{DBPacket, DBType};
use packets::mysql::MySQLPacket;

pub struct Executor {
    pub config: Config,
    rx: mpsc::Receiver<Vec<Box<dyn DBPacket>>>,
}

impl Executor {
    pub fn new(conf: Config, rx: mpsc::Receiver<Vec<Box<dyn DBPacket>>>) -> Executor {
        Executor { config: conf , rx}
    }
    pub async fn run(&mut self) {
        loop {
            match self.rx.recv().await {
                None => {
                    panic!("Executor: Channel closed");
                }
                Some(packets) => {
                    for pkt in packets {
                        let db_type = pkt.db_type();
                        match db_type {
                            DBType::MySQL => {
                                // do something
                                // packets -> mysql
                                let mysql_pkt = pkt.as_any().downcast_ref::<MySQLPacket>().unwrap();
                                info!("rx: MySQL Packet: {:?}", mysql_pkt);

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