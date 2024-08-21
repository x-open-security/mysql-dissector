use config::Config;
use log::{debug, error, info, warn};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpOption, TcpPacket};
use pnet::packet::Packet;
use std::collections::HashMap;
use std::error::Error;
use std::mem::swap;
use std::ops::Deref;

pub struct Capture {
    session_manager: SessionManager,
    config: Config,
}

impl Capture {
    pub fn new(conf: Config) -> Capture {
        Capture {
            session_manager: SessionManager::new(conf.clone()),
            config: conf.clone(),
        }
    }

    pub fn active(&mut self) {
        let conf = &self.config;
        info!("Capture started with config: {:?}", conf);

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
                Ok(packet) => {
                    // let pkt = self.session_manager.format_pkt_layer(&packet);
                    // if pkt.is_none() {
                    //     continue;
                    // }
                    // let pkt = pkt.unwrap();
                    self.session_manager.accept(packet);
                }
                Err(e) => {
                    error!("Error happened: {}", e);
                }
            }
        }
    }
}

pub struct SessionManager {
    sessions: HashMap<String, Session>,
    config: Config,
}

impl SessionManager {
    pub fn new(conf: Config) -> SessionManager {
        SessionManager {
            sessions: Default::default(),
            config: conf,
        }
    }

    fn to_eth_layer(&self, eth_pkt: &EthernetPacket) -> EthLayer {
        EthLayer {
            src_mac: eth_pkt.get_source().to_string(),
            dst_mac: eth_pkt.get_destination().to_string(),
            eth_type: eth_pkt.get_ethertype(),
        }
    }

    fn to_ip_layer(&self, ip_pkt: &Ipv4Packet) -> IpLayer {
        IpLayer {
            src_ip: ip_pkt.get_source().to_string(),
            dst_ip: ip_pkt.get_destination().to_string(),
        }
    }

    fn to_tcp_layer(&self, tcp_pkt: &TcpPacket) -> TcpLayer {
        TcpLayer {
            src_port: tcp_pkt.get_source(),
            dst_port: tcp_pkt.get_destination(),
            flags: tcp_pkt.get_flags(),
            options: tcp_pkt.get_options().to_vec(),
            payload: tcp_pkt.payload().to_vec(),
        }
    }

    fn db_type(&self, port: u16) -> Option<String> {
        self.config.support_db.get(&port.to_string()).cloned()
    }

    pub fn format_pkt_layer(&self, pkt: &[u8]) -> Option<SessionPacket> {
        // layer 2
        let eth = EthernetPacket::new(pkt)?.consume_to_immutable();
        let eth_type = eth.get_ethertype();

        // layer 3
        if eth_type != EtherTypes::Ipv4 {
            return None;
        }

        let ipv4 = Ipv4Packet::new(&eth.payload())?.consume_to_immutable();

        // layer 4
        let tcp_packet = match ipv4.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                Some(TcpPacket::new(ipv4.payload())?.consume_to_immutable())
            }
            _ => None,
        };

        if tcp_packet.is_none() {
            return None;
        }
        let tp = tcp_packet?;

        if tp.get_flags() & TcpFlags::PSH <= 0 {
            return None;
        }

        // format packet
        let eth_layer = self.to_eth_layer(&eth);
        let ip_layer = self.to_ip_layer(&ipv4);
        let tcp_layer = self.to_tcp_layer(&tp);
        let mut request = self
            .config
            .support_db
            .contains_key(&tcp_layer.dst_port.to_string())
            || self
                .config
                .support_db
                .contains_key(&tcp_layer.src_port.to_string());
        // check support db
        let db_type = if request {
            self.db_type(tcp_layer.dst_port)
        } else {
            self.db_type(tcp_layer.src_port)
        };

        if db_type.is_none() {
            return None;
        }

        // got session key
        let session_key = if request {
            format!(
                "{}:{}:{}:{}",
                ip_layer.src_ip, tcp_layer.src_port, ip_layer.dst_ip, tcp_layer.dst_port
            )
        } else {
            format!(
                "{}:{}:{}:{}",
                ip_layer.dst_ip, tcp_layer.dst_port, ip_layer.src_ip, tcp_layer.src_port
            )
        };

        Some(SessionPacket {
            eth_layer,
            ip_layer,
            tcp_layer,
            request,
            db: db_type?,
            session_key,
        })
    }

    pub fn accept(&mut self, pkt: &[u8]) {
        let pkt = match self.format_pkt_layer(pkt) {
            Some(pkt) => pkt,
            None => return,
        };


        let session_key = pkt.session_key.clone();
        let db_type = pkt.db.clone();

        if !self.sessions.contains_key(&session_key) {
            let session = self.create_session(pkt.clone(), db_type);
            self.sessions.insert(session_key.clone(), session);
        }

        if let Some(session) = self.sessions.get_mut(&session_key) {
            session.accept(pkt);
        }
    }

    pub fn create_session(&self, pkt: SessionPacket, db_type: String) -> Session {
        let session_ctx = self.create_session_ctx(&pkt, db_type);
        let session = Session::new(self.config.clone(), session_ctx);
        session
    }

    pub fn create_session_ctx(&self, pkt: &SessionPacket, db_type: String) -> SessionCtx {
        SessionCtx {
            state: SessionState::Unknown,
            src_ip: pkt.ip_layer.src_ip.clone(),
            dst_ip: pkt.ip_layer.dst_ip.clone(),
            src_port: pkt.tcp_layer.src_port.clone(),
            dst_port: pkt.tcp_layer.dst_port.clone(),
            src_mac: pkt.eth_layer.src_mac.clone(),
            dst_mac: pkt.eth_layer.dst_mac.clone(),
            db_type,
        }
    }
}

// impl future for async
#[derive(Debug, Clone)]
pub struct Session {
    ctx: SessionCtx,
    conf: Config,
}

impl Session {
    pub fn new(conf: Config, ctx: SessionCtx) -> Session {
        Session { ctx, conf }
    }

    pub fn accept(&mut self, pkt: SessionPacket) {
        info!("Accept packet: {:?}", pkt);
    }
}

#[derive(Debug, Clone)]
enum SessionState {
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
}

#[derive(Debug, Clone)]
pub struct SessionPacket {
    pub eth_layer: EthLayer,
    pub ip_layer: IpLayer,
    pub tcp_layer: TcpLayer,
    pub request: bool,
    pub db: String,
    pub session_key: String,
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
}

#[derive(Debug, Clone)]
pub struct TcpLayer {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub options: Vec<TcpOption>,
    pub payload: Vec<u8>,
}
