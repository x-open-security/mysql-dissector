use std::io::Cursor;
use bytes::Buf;
use crate::Command;
use crate::mysql::common::CLIENT_PROTOCOL_41;

pub struct  ErrPacket {
    pub header: Command,
    pub error_code: u16,
    pub sql_state_marker: Option<u8>,
    pub sql_state: Option<String>,
    pub error_message: String,
}

impl ErrPacket {
    pub fn new(cap:u32, payload: Vec<u8>) -> Self {
        let mut reader = Cursor::new(payload);
        let mut err_pkt = ErrPacket {
            header: Command(0),
            error_code:0,
            sql_state_marker: None,
            sql_state: None,
            error_message: String::new(),
        };
        let header = reader.get_u8();
        err_pkt.header = Command::from(header);
        let error_code = reader.get_u16_le();
        err_pkt.error_code = error_code;
        if cap & CLIENT_PROTOCOL_41 >0{
            let sql_state_marker = reader.get_u8();
            err_pkt.sql_state_marker = Some(sql_state_marker);
            let mut sql_state = String::new();
            for _ in 0..5 {
                let c = reader.get_u8();
                sql_state.push(c as char);
            }
            err_pkt.sql_state = Some(sql_state);
        }
        let mut error_message = String::new();
        loop {
            if  reader.remaining() <= 0 {
                break;
            }
            let c = reader.get_u8();
            if c == 0  {
                break;
            }
            error_message.push(c as char);
        }
        err_pkt.error_message = error_message;
        err_pkt
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_mysql57_err() {
        let packet_bytes = [
            0xff, 0x16, 0x04, 0x23,
            0x33, 0x44, 0x30, 0x30, 0x30, 0x4e, 0x6f, 0x20,
            0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65,
            0x20, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x65,
            0x64
        ];

        let err_packet = ErrPacket::new(CLIENT_PROTOCOL_41, packet_bytes.to_vec());

        if let ErrPacket {
            header,
            error_code,
            sql_state_marker,
            sql_state,
            error_message,
        } = err_packet {
            assert_eq!(header.0, 0xff);
            assert_eq!(error_code, 1046);
            assert_eq!(sql_state_marker, Some(0x23));
            assert_eq!(sql_state, Some("3D000".to_string()));
            assert_eq!(error_message, "No database selected".to_string());
        }
    }
}