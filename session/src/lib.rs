use config::Config;
use log::{debug, error, info};
use packets::mysql::common::{MySQLPacketRequest, MySQLPacketResponse};
use packets::mysql::server;
use packets::{DBPacket, DBType};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::tcp::TcpOption;
use pnet::packet::Packet;
use pnet_packet::ethernet::{EtherType, EtherTypes};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::error::Error;
use std::os::macos;
use std::str::FromStr;
use tokio::sync::mpsc::UnboundedReceiver;
#[derive(Debug, Clone)]
enum SessionState {
    ServerGreeting,
    ClientHandshakeResponse,
    Login,
    Logout,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SessionCtx {
    pub state: SessionState,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_mac: String,
    pub dst_mac: String,
    pub db_type: String,

    // parse mysql greeting packet
    pub server_cap: u32,
    pub client_cap: u32,
    pub server_status: u16,
    pub client_status: u16,
    pub server_language: u8,
    pub client_language: u8,
    pub server_version: String,
    pub client_version: String,
}

impl SessionCtx {
    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }
    pub fn set_server_version(&mut self, version: String) {
        self.server_version = version;
    }

    pub fn set_server_language(&mut self, language: u8) {
        self.server_language = language;
    }

    pub fn set_connection_id(&mut self, id: u32) {
        self.server_cap = id;
    }

    pub fn set_capability_flags(&mut self, flags: u32) {
        self.server_cap = flags;
    }

    pub fn set_status_flags(&mut self, flags: u16) {
        self.server_status = flags;
    }

    pub fn set_extended_capability_flags(&mut self, flags: u16) {
        self.client_status = flags;
    }

    pub fn set_auth_plugin_len(&mut self, len: u8) {
        self.server_language = len;
    }

    pub fn set_auth_plugin_data(&mut self, data: Vec<u8>) {
        self.server_language = data.len() as u8;
    }

    pub fn set_auth_plugin_data_2(&mut self, data: Vec<u8>) {
        self.server_language = data.len() as u8;
    }

    pub fn set_auth_plugin_name(&mut self, name: String) {
        self.server_version = name;
    }
}

#[derive(Debug, Clone)]
pub struct EthLayer {
    pub src_mac: String,
    pub dst_mac: String,
    pub eth_type: EtherType,
}

#[derive(Debug, Clone)]
pub struct IpLayer {
    pub src_ip: String,
    pub dst_ip: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TcpLayer {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub options: Vec<TcpOption>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SessionPacket {
    pub eth_layer: EthLayer,
    pub ip_layer: IpLayer,
    pub tcp_layer: TcpLayer,
    pub request: bool,
    pub db: DBType,
    pub session_key: String,
}

impl SessionPacket {
    pub fn new(config: &config::Config, raw_pkt: Vec<u8>) -> Option<Self> {
        // format eth
        let eth = EthernetPacket::new(raw_pkt.as_slice());

        if eth.is_none() {
            debug!("Failed to parse ethernet packet");
            return None;
        };

        let eth_pkt = eth?.consume_to_immutable();

        let ip_layer = if eth_pkt.get_ethertype() == EtherTypes::Ipv4 {
            let ip = Ipv4Packet::new(eth_pkt.payload());
            if ip.is_none() {
                error!("Failed to parse ipv4 packet");
                return None;
            };
            let ip_pkt = ip?.consume_to_immutable();
            Some(IpLayer {
                src_ip: ip_pkt.get_source().to_string(),
                dst_ip: ip_pkt.get_destination().to_string(),
                payload: ip_pkt.payload().to_vec(),
            })
        } else if eth_pkt.get_ethertype() == EtherTypes::Ipv6 {
            let ip = Ipv6Packet::new(eth_pkt.payload());
            if ip.is_none() {
                error!("Failed to parse ipv6 packet");
                return None;
            };
            let ip_pkt = ip?.consume_to_immutable();
            Some(IpLayer {
                src_ip: ip_pkt.get_source().to_string(),
                dst_ip: ip_pkt.get_destination().to_string(),
                payload: ip_pkt.payload().to_vec(),
            })
        } else {
            error!("Packet is not ipv4 or ipv6");
            None
        };

        if ip_layer.is_none() {
            error!("Failed to parse ip layer");
            return None;
        }

        let ip_layer = ip_layer.clone()?;
        let tcp_pkt = TcpPacket::new(ip_layer.payload.as_slice());

        if tcp_pkt.is_none() {
            error!("Failed to parse tcp packet");
            return None;
        }

        let tcp = tcp_pkt?.consume_to_immutable();

        let tcp_layer = TcpLayer {
            src_port: tcp.get_source(),
            dst_port: tcp.get_destination(),
            flags: tcp.get_flags(),
            options: tcp.get_options(),
            payload: tcp.payload().to_vec(),
        };

        let eth_layer = EthLayer {
            src_mac: eth_pkt.get_source().to_string(),
            dst_mac: eth_pkt.get_destination().to_string(),
            eth_type: eth_pkt.get_ethertype(),
        };

        let request = config
            .support_db
            .contains_key(&tcp.get_destination().to_string());

        let (db_type, sk) = if request {
            let dt = config.support_db.get(&tcp.get_destination().to_string());
            if dt.is_none() {
                debug!("Failed to get db type port {:?}", &tcp.get_destination());
                return None;
            } else {
                (
                    dt?.to_string(),
                    format!(
                        "{}{}{}-{}{}{}",
                        eth_layer.src_mac,
                        ip_layer.src_ip,
                        tcp_layer.src_port,
                        eth_layer.dst_mac,
                        ip_layer.dst_ip,
                        tcp_layer.dst_port
                    ),
                )
            }
        } else {
            let dt = config.support_db.get(&tcp.get_source().to_string());
            if dt.is_none() {
                debug!(
                    "Failed to get db type port {:?}",
                    &tcp.get_source().to_string()
                );
                return None;
            } else {
                (
                    dt?.to_string(),
                    format!(
                        "{}{}{}-{}{}{}",
                        eth_layer.dst_mac,
                        ip_layer.dst_ip,
                        tcp_layer.dst_port,
                        eth_layer.src_mac,
                        ip_layer.src_ip,
                        tcp_layer.src_port
                    ),
                )
            }
        };

        Some(SessionPacket {
            eth_layer,
            ip_layer: ip_layer.clone(),
            tcp_layer,
            request,
            db: DBType::from_str(db_type.as_str()).unwrap(),
            session_key: sk,
        })
    }
}

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

            SessionState::ClientHandshakeResponse => {
                if let SessionState::ClientHandshakeResponse = other {
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

                    if req_pkt.get_seq() == 1
                        && self.session_ctx.state == SessionState::ServerGreeting
                    {
                        info!("got client handshake response");
                        self.session_ctx
                            .set_state(SessionState::ClientHandshakeResponse);
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
                                info!("server greeting: {:?}", &greeting);
                                self.session_ctx.set_state(SessionState::ServerGreeting);
                                self.session_ctx.set_server_version(greeting.server_version);
                                self.session_ctx
                                    .set_server_language(greeting.server_language);
                                self.session_ctx.set_connection_id(greeting.connection_id);
                                self.session_ctx
                                    .set_capability_flags(greeting.capability_flags as u32);
                                self.session_ctx.set_status_flags(greeting.status_flags);
                                self.session_ctx.set_extended_capability_flags(
                                    greeting.extended_capability_flags,
                                );
                                self.session_ctx
                                    .set_auth_plugin_len(greeting.auth_plugin_len);
                                self.session_ctx
                                    .set_auth_plugin_data(greeting.auth_plugin_data);
                                self.session_ctx
                                    .set_auth_plugin_data_2(greeting.auth_plugin_data_2);
                                self.session_ctx
                                    .set_auth_plugin_name(greeting.auth_plugin_name);
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

    fn get_session(&mut self, session_key: &str) -> Option<&mut Session> {
        self.sessions.get_mut(session_key)
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
            server_cap: 0,
            client_cap: 0,
            server_status: 0,
            client_status: 0,
            server_language: 0,
            client_language: 0,
            server_version: "".to_string(),
            client_version: "".to_string(),
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
