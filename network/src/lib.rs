pub mod session_manager;
mod session;

use log::{debug, error, info};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::tcp::TcpOption;
use pnet::packet::Packet;
use pnet_packet::ethernet::{EtherType, EtherTypes};
use std::error::Error;
use std::str::FromStr;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use packets::DBType;

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
                debug!("Failed to get db type port {:?}", &tcp.get_source().to_string());
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
                    )
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
