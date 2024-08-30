use std::io::Cursor;
use bytes::Buf;
pub struct  EOFPacket  {
    pub header: u8,
    pub warnings: u16,
    pub status_flags: u16,
}

impl EOFPacket {
    pub fn new(cap:u32, payload: Vec<u8>) -> Self {
        let mut reader = Cursor::new(payload);
        let header = reader.get_u8();
        let warnings = reader.get_u16_le();
        let status_flags = reader.get_u16_le();
        EOFPacket {
            header,
            warnings,
            status_flags,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::mysql::common::CLIENT_PROTOCOL_41;
    use super::*;

    #[test]
    pub fn test_mysql57_eof() {
        let packet_bytes = [
            0xfe, 0x00, 0x00, 0x02, 0x00
        ];
        let eof_pkt = EOFPacket::new(CLIENT_PROTOCOL_41, packet_bytes.to_vec());
        assert_eq!(eof_pkt.header, 0xfe);
        assert_eq!(eof_pkt.warnings, 0x00);
        assert_eq!(eof_pkt.status_flags, 2);
    }
}