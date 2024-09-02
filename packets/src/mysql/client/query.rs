use std::io::Cursor;
use bytes::Buf;
use crate::Command;
pub struct  QueryPacket {
    pub cmd: Command,
    pub query: String,
}

impl QueryPacket {
    pub fn new(payload: Vec<u8>) -> Self {
        let mut reader = Cursor::new(payload);
        let mut query = String::new();
        let cmd = Command::from(reader.get_u8());
        loop {
            if reader.remaining() <= 0 {
                break;
            }
            let c = reader.get_u8();
            if c == 0 {
                break;
            }
            query.push(c as char);
        }
        QueryPacket {
            cmd,
            query
        }
    }
}


#[cfg(test)]
mod test {
    #[test]
    pub fn query_test() {
        use super::QueryPacket;
        use std::io::Cursor;

        let packet_bytes = [
            0x03, 0x53, 0x45, 0x54,
            0x20, 0x6e, 0x65, 0x74, 0x5f, 0x77, 0x72, 0x69,
            0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x6f,
            0x75, 0x74, 0x3d, 0x36, 0x30
        ];


        let mut reader = Cursor::new(packet_bytes);
        let query_packet = QueryPacket::new(packet_bytes.to_vec());
        assert_eq!(query_packet.cmd.0, 0x03);
        assert_eq!(query_packet.query, "SET net_write_timeout=60");
    }
}