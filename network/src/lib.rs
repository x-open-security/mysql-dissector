mod session;
pub mod session_manager;

use log::{debug, error, info};
use packets::DBType;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::tcp::TcpOption;
use pnet::packet::Packet;
use pnet_packet::ethernet::{EtherType, EtherTypes};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use std::error::Error;
use std::str::FromStr;

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
