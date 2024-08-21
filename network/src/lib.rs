use config::Config;
use log::{debug, error, info, warn};
use packets::mysql::MySQLProtocolPacket;
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
    manager: NetworkManager,
    config: Config,
}

impl Capture {
    pub fn new(conf: Config) -> Capture {
        Capture {
            manager: NetworkManager::new(conf.clone()),
            config: conf.clone(),
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
        let db_type = self.config.support_db.iter().find(|(k, v)| {
            return if port == v.parse().unwrap() {
                true
            } else {
                false
            };
        });

        match db_type {
            Some((k, _)) => Some(k.to_string()),
            None => None,
        }
    }

    pub fn run_block(&mut self) {
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
                    let eth = EthernetPacket::new(packet).unwrap().consume_to_immutable();
                    let eth_type = eth.get_ethertype();
                    match eth_type {
                        EtherTypes::Ipv4 => {
                            let ipv4 = Ipv4Packet::new(&eth.payload())
                                .unwrap()
                                .consume_to_immutable();

                            let tcp_packet = match ipv4.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => Some(
                                    TcpPacket::new(ipv4.payload())
                                        .unwrap()
                                        .consume_to_immutable(),
                                ),
                                // todo support udp
                                _ => continue,
                            };

                            match tcp_packet {
                                Some(tp) => {
                                    if (tp.get_flags() & TcpFlags::PSH > 0)
                                        && (tp.get_flags() & TcpFlags::ACK > 0)
                                    {
                                        let eth_layer = self.to_eth_layer(&eth);
                                        let ip_layer = self.to_ip_layer(&ipv4);
                                        let tcp_layer = self.to_tcp_layer(&tp);
                                        let mut request = false;
                                        let mut sb: String = "".parse().unwrap();
                                        let mut db_type = self.db_type(tcp_layer.dst_port);

                                        match db_type {
                                            Some(db) => {
                                                debug!("Found db type: {:?}", db);
                                                request = true;
                                                sb = db;
                                            }
                                            None => {
                                                db_type = self.db_type(tcp_layer.src_port);
                                                match db_type {
                                                    Some(db) => {
                                                        debug!("Found db type: {:?}", db);
                                                        sb = db
                                                    }
                                                    None => {
                                                        continue;
                                                    }
                                                }
                                            }
                                        }

                                        let session_key = if request {
                                            format!(
                                                "{}:{}:{}:{}",
                                                ip_layer.src_ip,
                                                tcp_layer.src_port,
                                                ip_layer.dst_ip,
                                                tcp_layer.dst_port
                                            )
                                        } else {
                                            format!(
                                                "{}:{}:{}:{}",
                                                ip_layer.dst_ip,
                                                tcp_layer.dst_port,
                                                ip_layer.src_ip,
                                                tcp_layer.src_port
                                            )
                                        };

                                        let pkt = SessionPacket {
                                            eth_layer,
                                            ip_layer,
                                            tcp_layer,
                                            request,
                                            db: sb,
                                            session_key,
                                        };

                                        self.manager.accept(pkt);
                                    }
                                }
                                None => continue,
                            }
                        }
                        // todo support ipv6
                        _ => {
                            debug!("Unsupported ether type: {:?}", eth_type);
                        }
                    }
                }
                Err(e) => {
                    error!("Error happened: {}", e);
                }
            }
        }
    }
}

pub struct NetworkManager {
    sessions: HashMap<String, Session>,
    config: Config,
}

impl NetworkManager {
    pub fn new(conf: Config) -> NetworkManager {
        NetworkManager {
            sessions: Default::default(),
            config: conf,
        }
    }

    pub fn accept(&mut self, pkt: SessionPacket) {
        let session_key = &pkt.session_key.clone();
        let db_type = &pkt.db.clone();
        if self.sessions.contains_key(session_key) {
            let session = self.sessions.get_mut(session_key).unwrap();
            session.accept(pkt);
        } else {
            let mut session = self.create_session(pkt.clone(), db_type.clone());
            session.accept(pkt);
            self.sessions.insert(session_key.clone(), session.clone());
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
    current_seq_num: u8,
    tmp_packets: Vec<SessionPacket>,
}

impl Session {
    pub fn new(conf: Config, ctx: SessionCtx) -> Session {
        match ctx.db_type.as_str() {
            "mysql" => Session {
                ctx,
                conf,
                current_seq_num: 0,
                tmp_packets: vec![],
            },
            _ => {
                panic!("Unsupported db type: {:?}", ctx.db_type);
            }
        }
    }

    pub fn accept(&mut self, pkt: SessionPacket) {
        info!("Accept packet: {:?}", pkt);
        if pkt.request {
            let proto_pkt = MySQLProtocolPacket::new(pkt.tcp_layer.payload.as_slice());
            match proto_pkt {
                Some(p) => {
                    if p.get_seq() < self.current_seq_num {
                        self.flush();
                    } else {
                        self.current_seq_num = p.get_seq();
                        self.tmp_packets.push(pkt.clone());
                    }

                    info!(
                        "MySQLProtocolPacket: packet header {:?}, packet payload: {:?}",
                        p,
                        p.payload()
                    );
                }
                None => {
                    warn!("Not a MySQLProtocolPacket");
                }
            }
        } else {
            debug!("todo")
        }
    }

    pub fn flush(&mut self) {
        let mut packets = vec![];
        swap(&mut packets, &mut self.tmp_packets);
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
