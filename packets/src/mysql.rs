use pnet_macros::packet;
use pnet_macros_support::types::{u16le, u24le, u32le};
use pnet_packet::PrimitiveValues;
use std::collections::HashMap;

/// Documentation for MyProtocolField
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct Command(pub u8);

impl Command {
    pub fn new(field_val: u8) -> Command {
        Command(field_val)
    }
}

impl PrimitiveValues for Command {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod CMDValues {
    use super::Command;
    pub const QUERY: Command = Command(0x03);
}

#[packet]
pub struct MySQLProtocolRequest {
    pub len: u24le,
    #[construct_with(u8)]
    pub seq: u8,
    #[construct_with(u8)]
    pub cmd: Command,
    #[payload]
    pub payload: Vec<u8>,
}

// pub struct LoginRequest {
//     pub client_flags: u16le,
//     pub client_extended_flags: u16le,
//     pub max_packet_size: u32le,
//     pub charset: u8,
//     #[construct_with(u8)]
//     pub reserved: [u8; 23],
//     #[construct_with(u8)]
//     pub user: Vec<u8>,
//     #[construct_with(u8)]
//     pub password: Vec<u8>,
//     #[construct_with(u8)]
//     pub db: Vec<u8>,
//     #[construct_with(u8)]
//     pub auth_plugin_name: Vec<u8>,
//
//     pub attributes: HashMap<String, String>,
// }
