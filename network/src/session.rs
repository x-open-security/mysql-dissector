use std::cmp::PartialEq;
use std::os::macos;
use crate::{SessionCtx, SessionPacket, SessionState};
use log::info;
use packets::mysql::{server, MySQLPacketRequest, MySQLPacketResponse};
use packets::{DBPacket, DBType};

pub struct Session {
    session_ctx: SessionCtx,
    pkt_seq: u8,
    flow_packets: Vec<Box<dyn DBPacket>>,
}

impl PartialEq for SessionState {
    fn eq(&self, other: &Self) -> bool {
        match self {
            SessionState::ServerGreeting => {
                if let SessionState::ServerGreeting = other {
                    return true;
                }
            }
            SessionState::Login => {
                if let SessionState::Login = other {
                    return true;
                }
            }
            SessionState::Logout => {
                if let SessionState::Logout = other {
                    return true;
                }
            }
            SessionState::Unknown => {
                if let SessionState::Unknown = other {
                    return true;
                }
            }
        }
        false
    }
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

                    if req_pkt.get_seq() == 1 && self.session_ctx.state == SessionState::ServerGreeting {
                        info!("got client handshake response");
                        self.session_ctx.set_state(SessionState::ClientHandshakeResponse);

                    }

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
                        match server::greeting::Greeting::new(resp_pkt.get_payload()) {
                            Some(greeting) => {
                                self.session_ctx.set_state(SessionState::ServerGreeting);
                                self.session_ctx.set_server_version(greeting.server_version);
                                self.session_ctx.set_server_language(greeting.server_language);
                                self.session_ctx.set_connection_id(greeting.connection_id);
                                self.session_ctx.set_capability_flags(greeting.capability_flags as u32);
                                self.session_ctx.set_status_flags(greeting.status_flags);
                                self.session_ctx.set_extended_capability_flags(greeting.extended_capability_flags);
                                self.session_ctx.set_auth_plugin_len(greeting.auth_plugin_len);
                                self.session_ctx.set_auth_plugin_data(greeting.auth_plugin_data);
                                self.session_ctx.set_auth_plugin_data_2(greeting.auth_plugin_data_2);
                                self.session_ctx.set_auth_plugin_name(greeting.auth_plugin_name);
                                info!("server greeting: {:?}", greeting);
                            }
                            None => {
                                info!("failed to parse server greeting");
                            }
                        }
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
