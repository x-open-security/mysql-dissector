pub mod client;
pub mod server;

pub mod common {
    use crate::{Command, DBPacket, DBType};
    use bytes::Buf;
    use std::any::Any;
    use std::io::Cursor;

    // client cap
    pub const CLIENT_LONG_PASSWORD: u32 = 1;
    pub const CLIENT_FOUND_ROWS: u32 = 2;
    pub const CLIENT_LONG_FLAG: u32 = 4;
    pub const CLIENT_CONNECT_WITH_DB: u32 = 8;
    pub const CLIENT_NO_SCHEMA: u32 = 16;
    pub const CLIENT_COMPRESS: u32 = 32;
    pub const CLIENT_ODBC: u32 = 64;
    pub const CLIENT_LOCAL_FILES: u32 = 128;
    pub const CLIENT_IGNORE_SPACE: u32 = 256;
    pub const CLIENT_PROTOCOL_41: u32 = 512;
    pub const CLIENT_INTERACTIVE: u32 = 1024;
    pub const CLIENT_SSL: u32 = 2048;
    pub const CLIENT_IGNORE_SIGPIPE: u32 = 4096;
    pub const CLIENT_TRANSACTIONS: u32 = 8192;
    pub const CLIENT_RESERVED: u32 = 16384;
    pub const CLIENT_RESERVED2: u32 = 32768;
    pub const CLIENT_MULTI_STATEMENTS: u32 = 1 << 16;
    pub const CLIENT_MULTI_RESULTS: u32 = 1 << 17;
    pub const CLIENT_PS_MULTI_RESULTS: u32 = 1 << 18;
    pub const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;
    pub const CLIENT_CONNECT_ATTRS: u32 = 1 << 20;
    pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 1 << 21;
    pub const CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS: u32 = 1 << 22;
    pub const CLIENT_SESSION_TRACK: u32 = 1 << 23;
    pub const CLIENT_DEPRECATE_EOF: u32 = 1 << 24;
    pub const CLIENT_OPTIONAL_RESULTSET_METADATA: u32 = 1 << 25;
    pub const CLIENT_ZSTD_COMPRESSION_ALGORITHM: u32 = 1 << 26;
    pub const CLIENT_QUERY_ATTRIBUTES: u32 = 1 << 27;
    pub const MULTI_FACTOR_AUTHENTICATION: u32 = 1 << 28;
    pub const CLIENT_CAPABILITY_EXTENSION: u32 = 1 << 29;
    pub const CLIENT_SSL_VERIFY_SERVER_CERT: u32 = 1 << 30;
    pub const CLIENT_REMEMBER_OPTIONS: u32 = 1 << 31;

    // server status flag
    pub const SERVER_STATUS_IN_TRANS: u32 = 1;
    pub const SERVER_STATUS_AUTOCOMMIT: u32 = 2;
    pub const SERVER_MORE_RESULTS_EXISTS: u32 = 8;
    pub const SERVER_QUERY_NO_GOOD_INDEX_USED: u32 = 16;
    pub const SERVER_QUERY_NO_INDEX_USED: u32 = 32;
    pub const SERVER_STATUS_CURSOR_EXISTS: u32 = 64;
    pub const SERVER_STATUS_LAST_ROW_SENT: u32 = 128;
    pub const SERVER_STATUS_DB_DROPPED: u32 = 256;
    pub const SERVER_STATUS_NO_BACKSLASH_ESCAPES: u32 = 512;
    pub const SERVER_STATUS_METADATA_CHANGED: u32 = 1024;
    pub const SERVER_QUERY_WAS_SLOW: u32 = 2048;
    pub const SERVER_PS_OUT_PARAMS: u32 = 4096;
    pub const SERVER_STATUS_IN_TRANS_READONLY: u32 = 8192;
    pub const SERVER_SESSION_STATE_CHANGED: u16 = 1 << 14;

    // command
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
    }

    pub fn read_len_enc_int(payload: &mut Cursor<&[u8]>) -> (u64, usize) {
        let mut len = 0;
        let mut pos = 0;
        let mut shift = 0;
        loop {
            let b = payload.get_u8();
            pos += 1;
            len |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        (len, pos)
    }

    pub fn read_len_enc_str(payload: &mut Cursor<&[u8]>) -> (String, usize) {
        let (len, pos) = read_len_enc_int(payload);
        let start = payload.position() as usize;
        let end = start + len as usize;
        let s = String::from_utf8(payload.get_ref()[start..end].to_vec()).unwrap();
        (s, pos + len as usize)
    }
}
