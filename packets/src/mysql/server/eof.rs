use crate::mysql::common::CLIENT_PROTOCOL_41;
use bytes::Buf;
use std::io::Cursor;
use crate::Command;

pub struct EOFPacket {
    pub header: Command,
    pub warnings: u16,
    pub status_flags: u16,
}

impl EOFPacket {
    pub fn new(cap: u32, payload: Vec<u8>) -> Self {
        let mut reader = Cursor::new(payload);
        let header = reader.get_u8();
        let mut eof_pkt = EOFPacket {
            header: Command::from(header),
            warnings: 0,
            status_flags: 0,
        };
        if cap & CLIENT_PROTOCOL_41 > 0 {
            let warnings = reader.get_u16_le();
            let status_flags = reader.get_u16_le();
            eof_pkt.warnings = warnings;
            eof_pkt.status_flags = status_flags;
        }

        eof_pkt
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mysql::common::CLIENT_PROTOCOL_41;

    #[test]
    pub fn test_mysql57_eof() {
        let packet_bytes = [0xfe, 0x00, 0x00, 0x02, 0x00];
        let eof_pkt = EOFPacket::new(CLIENT_PROTOCOL_41, packet_bytes.to_vec());
        assert_eq!(eof_pkt.header.0, 0xfe);
        assert_eq!(eof_pkt.warnings, 0x00);
        assert_eq!(eof_pkt.status_flags, 2);
    }
}
