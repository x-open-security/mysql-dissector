use log::info;
use crate::{SessionCtx, SessionPacket};
use packets::mysql::{MySQLPacketRequest, MySQLPacketResponse};
use packets::{DBPacket, DBType};

pub struct Session {
    session_ctx: SessionCtx,
    pkt_seq: u8,
    flow_packets: Vec<Box<dyn DBPacket>>,
}

impl Session {
    pub fn new(session_ctx: SessionCtx) -> Session {
        Session {
            session_ctx,
            pkt_seq: 0,
            flow_packets: Vec::new(),
        }
    }

    pub async fn accept(&mut self, pkt: SessionPacket) {
        // do something
        match pkt.db {
            DBType::MySQL => {
                if pkt.request {
                    let req_pkt = match MySQLPacketRequest::new(&pkt.tcp_layer.payload) {
                        Some(pkt) => pkt,
                        None => return,
                    };

                    if req_pkt.get_seq() < self.pkt_seq {
                        self.flush();
                    }

                    self.pkt_seq = req_pkt.get_seq();
                    self.flow_packets.push(Box::new(req_pkt));

                } else {
                    let resp_pkt = match MySQLPacketResponse::new(&pkt.tcp_layer.payload) {
                        Some(pkt) => pkt,
                        None => return,
                    };

                    if self.pkt_seq == 0 && resp_pkt.get_seq() == 0 {
                        info!("got server hello packet");

                        return;
                    }

                    self.flow_packets.push(Box::new(resp_pkt));

                }
            }
            _ => {}
        }
    }
    fn flush(&self) {
        // do something
    }
}
