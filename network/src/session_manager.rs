use crate::session::Session;
use crate::{SessionCtx, SessionPacket, SessionState};
use config::Config;
use log::error;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::format;
use tokio::sync::mpsc::UnboundedReceiver;
pub struct SessionManager {
    config: Config,
    rx: UnboundedReceiver<SessionPacket>,
    state: bool,
    sessions: HashMap<String, Session>,
}

impl SessionManager {
    pub fn new(config: Config, rx: UnboundedReceiver<SessionPacket>) -> SessionManager {
        SessionManager {
            config,
            rx,
            state: false,
            sessions: HashMap::new(),
        }
    }

    pub async fn run(&mut self) {
        self.state = true;
        loop {
            match self.rx.recv().await {
                None => {
                    error!("Executor channel closed");
                }
                Some(session_pkt) => {
                    if !self.check_session(&session_pkt.session_key) {
                        self.create_session(session_pkt.clone());
                    }

                    let res = self.parse_session_pkt(session_pkt).await;

                    if let Err(e) = res {
                        error!("Error happened: {}", e);
                    }
                }
            }
        }
    }

    fn check_session(&self, session_key: &str) -> bool {
        self.sessions.contains_key(session_key)
    }

    fn get_session(&self, session_key: &str) -> Option<&Session> {
        self.sessions.get(session_key)
    }

    fn create_session(&mut self, sess_pkt: SessionPacket) {
        let sctx = self.create_session_ctx(sess_pkt.clone());
        let session = Session::new(sctx);
        self.sessions
            .insert(sess_pkt.session_key.to_string(), session);
    }

    fn create_session_ctx(&self, sp: SessionPacket) -> SessionCtx {
        SessionCtx {
            state: SessionState::Unknown,
            src_ip: sp.ip_layer.src_ip.clone(),
            dst_ip: sp.ip_layer.dst_ip.clone(),
            src_port: sp.tcp_layer.src_port,
            dst_port: sp.tcp_layer.dst_port,
            src_mac: sp.eth_layer.src_mac.clone(),
            dst_mac: sp.eth_layer.dst_mac.clone(),
            db_type: sp.db.to_string(),
        }
    }

    async fn parse_session_pkt(&mut self, pkt: SessionPacket) -> Result<(), Box<dyn Error>> {
        let session = self.get_session(&pkt.session_key);
        match session {
            None => {
                let err = format!("Session not found: {}", pkt.session_key);
                Err(err.into())
            }
            Some(session) => {
                session.accept(pkt).await;
                Ok(())
            }
        }
    }

    pub fn is_running(&self) -> bool {
        self.state
    }
}
