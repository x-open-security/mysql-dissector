use config::Config;
use log::{debug, error, info, warn};
use packets::mysql::{MySQLPacketRequest, MySQLPacketResponse};
use packets::DBPacket;
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
use tokio::sync::mpsc;

pub struct Capture {
    session_manager: SessionManager,
    config: Config,
}

impl Capture {
    pub fn new(conf: Config, sender: mpsc::UnboundedSender<Vec<Box<dyn DBPacket>>>) -> Capture {
        Capture {
            session_manager: SessionManager::new(conf.clone(), sender),
            config: conf.clone(),
        }
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
                Ok(packet) => {
                    self.session_manager.accept(packet).await;
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
    sender: mpsc::UnboundedSender<Vec<Box<dyn DBPacket>>>,
}

impl SessionManager {
    pub fn new(
        conf: Config,
        sender: mpsc::UnboundedSender<Vec<Box<dyn DBPacket>>>,
    ) -> SessionManager {
        SessionManager {
            sessions: Default::default(),
            config: conf,
            sender,
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

    pub fn format_pkt_layer(&mut self, pkt: &[u8]) -> Option<SessionPacket> {
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

        // format packet
        let eth_layer = self.to_eth_layer(&eth);
        let ip_layer = self.to_ip_layer(&ipv4);
        let tcp_layer = self.to_tcp_layer(&tp);
        let request = self
            .config
            .support_db
            .iter()
            .any(|(port, _)| *port == tcp_layer.dst_port.to_string());

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

        if tp.get_flags() & TcpFlags::FIN > 0 || tp.get_flags() & TcpFlags::RST > 0 {
            info!("Session closed: {:?}", session_key);
            if self.sessions.contains_key(&session_key) {
                self.sessions.remove(&session_key);
            }
            return None;
        }

        if tp.get_flags() & TcpFlags::PSH <= 0 && tp.get_flags() & TcpFlags::ACK <= 0 {
            return None;
        }

        Some(SessionPacket {
            eth_layer,
            ip_layer,
            tcp_layer,
            request,
            db: db_type?,
            session_key,
        })
    }

    pub async fn accept(&mut self, pkt: &[u8]) {
        let pkt = match self.format_pkt_layer(pkt) {
            Some(pkt) => pkt,
            None => return,
        };

        let session_key = pkt.session_key.clone();
        let db_type = pkt.db.clone();

        // check session
        let mut session = self.sessions.get_mut(&session_key);

        match session {
            Some(sess) => {
                sess.accept(pkt).await;
            }
            None => {
                let conf = self.config.clone();
                let sender = self.sender.clone();
                let session_ctx = self.create_session_ctx(&pkt, db_type);
                let new_sess = Session::new(conf, session_ctx, sender);
                self.sessions.insert(session_key.clone(), new_sess.clone());
            }
        }
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
#[derive(Clone)]
pub struct Session {
    ctx: SessionCtx,
    conf: Config,
    packets: Vec<Box<dyn DBPacket>>,
    seq: u8,
    sender: mpsc::UnboundedSender<Vec<Box<dyn DBPacket>>>,
}

impl Session {
    fn from(value: Session) -> Self {
        Self {
            ctx: value.ctx,
            conf: value.conf,
            packets: value.packets,
            seq: value.seq,
            sender: value.sender,
        }
    }

    pub fn new(
        conf: Config,
        ctx: SessionCtx,
        sender: mpsc::UnboundedSender<Vec<Box<dyn DBPacket>>>,
    ) -> Session {
        Session {
            ctx,
            conf,
            packets: vec![],
            seq: 0,
            sender,
        }
    }

    pub async fn accept(&mut self, pkt: SessionPacket) {
        debug!("session.accept: {:?}", pkt);
        if pkt.request {
            let my_pkt = MySQLPacketRequest::new(&pkt.tcp_layer.payload);
            if my_pkt.is_none() {
                warn!("Not a mysql request packet");
                return;
            }
            let my_pkt = my_pkt.unwrap();
            info!("Got mysql request packet: {:?}", my_pkt);
            if my_pkt.seq < self.seq {
                info!("Got new flow seq: {}, old seq: {}", my_pkt.seq, self.seq);
                self.flush().await;
            }
            self.seq = my_pkt.seq;
            self.packets.push(Box::new(my_pkt));
        } else {
            let my_pkt = MySQLPacketResponse::new(&pkt.tcp_layer.payload);
            if my_pkt.is_none() {
                warn!("Not a mysql resp packet");
                return;
            }
            let my_pkt = my_pkt.unwrap();
            info!("Got mysql response packet: {:?}", my_pkt);
            self.seq = my_pkt.first_pkt_seq;
            self.packets.push(Box::new(my_pkt));
        }
    }

    async fn flush(&mut self) {
        if self.packets.is_empty() {
            return;
        }

        let mut tmp = vec![];
        swap(&mut tmp, &mut self.packets);
        if self.sender.is_closed() {

        }
        match self.sender.send(tmp) {
            Ok(_) => {
                info!("Send packets to sender");
            }
            Err(e) => {
                error!("Error happened: {}", e);
            }
        }
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
