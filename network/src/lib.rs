use config::Config;
use log::{debug, error, info, warn};
use packets::mysql::{MySQLProtocolRequestPacket};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpFlags, TcpOption, TcpPacket};
use pnet::packet::Packet;
use std::collections::HashMap;
use std::error::Error;
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
                            let ipv4 = Ipv4Packet::new(eth.payload())
                                .unwrap()
                                .consume_to_immutable();

                            let tcp_packet = match ipv4.get_next_level_protocol() {
                                IpNextHeaderProtocols::Tcp => Some(
                                    TcpPacket::new(ipv4.payload())
                                        .unwrap()
                                        .consume_to_immutable(),
                                ),
                                _ => continue,
                            };

                            match tcp_packet {
                                Some(tp) => {
                                    if (tp.get_flags() & TcpFlags::PSH > 0)
                                        && (tp.get_flags() & TcpFlags::ACK > 0)
                                    {
                                        self.manager.accept(&mut SessionPacket {
                                            tcp_pkt: &tp,
                                            eth_pkt: &eth,
                                            ip_pkt: &ipv4,
                                            request: false,
                                        });
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

    pub fn db_type(&self, port: u16) -> Option<String> {
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

    pub fn gen_session_key(&self, pkt: SessionPacket) -> String {
        let key = if pkt.request {
            format!(
                "{}:{}:{}:{}:{}:{}",
                pkt.ip_pkt.get_source(),
                pkt.tcp_pkt.get_source(),
                pkt.ip_pkt.get_destination(),
                pkt.tcp_pkt.get_destination(),
                pkt.eth_pkt.get_source(),
                pkt.eth_pkt.get_destination()
            )
        } else {
            format!(
                "{}:{}:{}:{}:{}:{}",
                pkt.ip_pkt.get_destination(),
                pkt.tcp_pkt.get_destination(),
                pkt.ip_pkt.get_source(),
                pkt.tcp_pkt.get_source(),
                pkt.eth_pkt.get_destination(),
                pkt.eth_pkt.get_source()
            )
        };

        key
    }

    pub fn accept(&mut self, pkt: &mut SessionPacket) {
        // find db type && ensure packet request or response
        let mut request = false;
        let mut db_type = self.db_type(pkt.tcp_pkt.get_destination());

        match db_type {
            Some(_) => {
                request = true;
            }
            None => {
                debug!("No db type found, try to find by source port");
                db_type = self.db_type(pkt.tcp_pkt.get_source());
            }
        }

        if db_type.is_none() {
            return;
        }

        pkt.request = request;
        info!("Found db type: {:?}", db_type);
        // find or create session
        let session_key = self.gen_session_key(pkt.clone());

        let session = {
            let session = self.sessions.get(&session_key);
            match session {
                Some(s) => {
                    info!("Found session: {:?}", s);
                    s.clone()
                }
                None => {
                    let session = self.create_session(pkt.clone(), db_type.unwrap());
                    self.sessions.insert(session_key.clone(), session.clone());
                    info!("Create new session: {:?}", session);
                    session
                }
            }
        };

        session.accept(pkt.clone());
    }

    pub fn create_session(&self, pkt: SessionPacket, db_type: String) -> Session {
        let session_ctx = self.create_session_ctx(&pkt, db_type);
        let session = Session::new(self.config.clone(), session_ctx);

        session
    }

    pub fn create_session_ctx(&self, pkt: &SessionPacket, db_type: String) -> SessionCtx {
        let session_ctx = || -> SessionCtx {
            if pkt.request {
                SessionCtx {
                    state: SessionState::Unknown,
                    src_ip: pkt.ip_pkt.get_source().to_string(),
                    dst_ip: pkt.ip_pkt.get_destination().to_string(),
                    src_port: pkt.tcp_pkt.get_source(),
                    dst_port: pkt.tcp_pkt.get_destination(),
                    src_mac: pkt.eth_pkt.get_source().to_string(),
                    dst_mac: pkt.eth_pkt.get_destination().to_string(),
                    db_type,
                }
            } else {
                SessionCtx {
                    state: SessionState::Unknown,
                    src_ip: pkt.ip_pkt.get_destination().to_string(),
                    dst_ip: pkt.ip_pkt.get_source().to_string(),
                    src_port: pkt.tcp_pkt.get_destination(),
                    dst_port: pkt.tcp_pkt.get_source(),
                    src_mac: pkt.eth_pkt.get_destination().to_string(),
                    dst_mac: pkt.eth_pkt.get_source().to_string(),
                    db_type,
                }
            }
        }();

        session_ctx
    }
}

// impl future for async
#[derive(Debug, Clone)]
pub struct Session<'a> {
    ctx: SessionCtx,
    conf: Config,
    current_seq_num: u8,
    tmp_packets: Vec<SessionPacket<'a>>,
}

impl Session {
    pub fn new(conf: Config, ctx: SessionCtx) -> Session {
        Session { ctx, conf, current_seq_num: 0, tmp_packets: vec![] }
    }

    pub fn accept(&mut self, pkt: SessionPacket) {
        info!("Accept packet: {:?}", pkt);
        if pkt.request {
            let proto_pkt = MySQLProtocolRequestPacket::new(pkt.tcp_pkt.payload());
            match proto_pkt {
                Some(p) => {
                    if p.get_seq() < self.current_seq_num {
                        self.flush();
                    } else {
                        self.current_seq_num = p.get_seq();
                        self.tmp_packets.push(pkt);
                    }

                    info!("MySQLProtocolPacket: packet header {:?}, packet payload: {:?}", p, p.payload());
                }
                None => {
                    warn!("Not a MySQLProtocolPacket");
                }
            }
        } else {
           debug!("todo")
        }
    }

    fn flush(&mut self) {
        let packets = self.tmp_packets.clone();
        self.tmp_packets.clear();


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
pub struct SessionPacket<'a> {
    pub eth_pkt: &'a EthernetPacket<'a>,
    pub ip_pkt: &'a Ipv4Packet<'a>,
    pub tcp_pkt: &'a TcpPacket<'a>,
    pub request: bool,
}
