use config::Config;
use log::info;
use pnet_macros::packet;
use pnet_macros_support::packet::Packet;
use pnet_macros_support::types::u24le;
use pnet_packet::PrimitiveValues;
use std::collections::HashMap;
use std::io::Error;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct Command(pub u8);

impl Command {
    pub fn new(field_val: u8) -> Command {
        Command(field_val)
    }

    pub fn parse(&self, pkt: MySQLProtocolPacket) -> Result<(), Error> {
        match Command(self.0) {
            CMDValues::QUERY => Command::parse_query(pkt),

            _ => Ok(()),
        }
    }

    fn parse_query(pkt: MySQLProtocolPacket) -> Result<(), Error> {
        let payload = pkt.payload();
        let query = String::from_utf8_lossy(payload);
        info!("Query: {}", query);
        Ok(())
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
    pub const QUIT: Command = Command(0x01);
    pub const INIT_DB: Command = Command(0x02);
    pub const QUERY: Command = Command(0x03);
    pub const FIELD_LIST: Command = Command(0x04);
    pub const STATISTICS: Command = Command(0x08);
    pub const DEBUG: Command = Command(0x0D);
    pub const PING: Command = Command(0x0E);
    pub const RESET_CONNECTION: Command = Command(0x1F);
    pub const SET_OPTION: Command = Command(0x1A);
    pub const CHANGE_USER: Command = Command(0x11);
    pub const BINLOG_DUMP: Command = Command(0x12);
    pub const STMT_PREPARE: Command = Command(0x16);
    pub const STMT_EXECUTE: Command = Command(0x17);
    pub const STMT_CLOSE: Command = Command(0x19);
    pub const STMT_RESET: Command = Command(0x1A);
    pub const STMT_SEND_LONG_DATA: Command = Command(0x18);
    pub const LOCAL_INFILE: Command = Command(0xfb);
    pub const OK: Command = Command(0x00);
    pub const ERR: Command = Command(0xff);
    pub const EOF: Command = Command(0xfe);
}

#[packet]
pub struct MySQLProtocol {
    pub len: u24le,
    #[construct_with(u8)]
    pub seq: u8,
    #[construct_with(u8)]
    pub cmd: Command,
    #[payload]
    pub payload: Vec<u8>,
}

pub struct MySQLParser {
    config: Config,
}

impl MySQLParser {
    pub fn new(config: Config) -> MySQLParser {
        MySQLParser { config }
    }

    pub fn parse(&self, packet: Vec<MySQLProtocolPacket>) -> Result<(), Error> {
        for pkt in packet {
            let cmd = pkt.get_cmd();
            cmd.parse(pkt)?;
        }
        Ok(())
    }
}
