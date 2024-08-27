pub mod server;

use crate::DBType;
use crate::{Command, DBPacket};
use pnet_macros_support::packet::Packet;
use std::any::Any;

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

#[derive(Debug, Clone)]
pub struct MySQLPacketRequest {
    len: u32,
    pub seq: u8,
    cmd: Command,
    payload: Vec<u8>,
}

impl MySQLPacketRequest {
    pub fn new(payload: &[u8]) -> Option<MySQLPacketRequest> {
        if payload.len() < 5 {
            return None;
        }
        let len = u32::from_le_bytes([payload[0], payload[1], payload[2], 0]);
        let seq = payload[3];
        let cmd = Command(payload[4]);

        Some(MySQLPacketRequest {
            len,
            seq,
            cmd,
            payload: payload[5..].to_vec(),
        })
    }
}

impl DBPacket for MySQLPacketRequest {
    fn db_type(&self) -> DBType {
        DBType::MySQL
    }

    fn get_command(&self) -> Command {
        self.cmd.clone()
    }

    fn get_payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    fn get_seq(&self) -> u8 {
        self.seq
    }

    fn get_len(&self) -> u32 {
        self.len
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_request(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct MySQLPacketResponse {
    pub first_pkt_len: u32,
    pub first_pkt_seq: u8,
    pub first_pkt_cmd: Command,
    pub payload: Vec<u8>,
}

impl MySQLPacketResponse {
    pub fn new(payload: &[u8]) -> Option<MySQLPacketResponse> {
        if payload.len() < 5 {
            return None;
        }
        let first_pkt_len = u32::from_le_bytes([payload[0], payload[1], payload[2], 0]);
        let first_pkt_seq = payload[3];
        let first_pkt_cmd = Command(payload[4]);

        Some(MySQLPacketResponse {
            first_pkt_len,
            first_pkt_seq,
            first_pkt_cmd,
            payload: payload.to_vec(),
        })
    }
}

impl DBPacket for MySQLPacketResponse {
    fn db_type(&self) -> DBType {
        DBType::MySQL
    }

    fn get_command(&self) -> Command {
        self.first_pkt_cmd.clone()
    }

    fn get_payload(&self) -> Vec<u8> {
        self.payload.clone()
    }

    fn get_seq(&self) -> u8 {
        self.first_pkt_seq
    }

    fn get_len(&self) -> u32 {
        self.first_pkt_len
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn is_request(&self) -> bool {
        false
    }
}

pub struct MySQLParser {}

impl MySQLParser {
    pub fn new() -> MySQLParser {
        MySQLParser {}
    }

    // pub async fn parse(&self, ) -> Option<Box<dyn DBPacket>> {
    //
    // }
}
