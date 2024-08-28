use crate::mysql::common::*;
use bytes::Buf;
use log::{error, info};
use std::collections::HashMap;
use std::io::prelude::*;
use std::io::Cursor;
#[derive(Debug, Default)]
pub struct Login {
    pub cap: u32,
    pub max_packet_size: u32,
    pub charset: u8,
    pub filler: [u8; 23],
    pub username: Option<String>, // terminated by 0x00, maybe null
    pub auth_response_length: u8,
    pub auth_response: Option<Vec<u8>>,    // var len
    pub database: Option<String>,         // terminated by 0x00, maybe null
    pub auth_plugin_name: Option<String>, // terminated by 0x00, maybe null
    pub attrs: HashMap<String, String>,
    pub zstd_compression_level: Option<u8>,
}

impl Login {
    pub fn new(payload: Vec<u8>) -> Option<Self> {
        let mut buf = Cursor::new(payload);
        let mut login = Login::default();
        let cap = buf.get_u32_le();
        login.cap = cap;
        info!("login cap: {}", cap);
        let max_packet_size = buf.get_u32_le();
        login.max_packet_size = max_packet_size;
        info!("login max_packet_size: {}", max_packet_size);
        let charset = buf.get_u8();
        login.charset = charset;
        info!("login charset: {}", charset);
        let mut filler = [0; 23];
        for i in 0..23 {
            filler[i] = buf.get_u8();
            if filler[i] != 0 {
                error!("mysql login filler field is not 0");
                return None;
            }
        }
        login.filler = filler;

        info!("login filler: {:?}", filler);

        let mut username = String::new();
        loop {
            let c = buf.get_u8();
            if c == 0x00 {
                break;
            }
            username.push(c as char);
        }

        login.username = Option::from(username);

        if buf.remaining() <= 0 {
            return Some(login);
        }

        if cap & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA > 0  {
            let auth_response_length = buf.get_u8();
            login.auth_response_length = auth_response_length;
            let mut auth_response = Vec::new();
            for i in 0..auth_response_length {
                auth_response.push(buf.get_u8());
            }
            login.auth_response = Some(auth_response);
        }

        if cap & CLIENT_CONNECT_WITH_DB > 0 && buf.remaining() > 0 {
            let mut database = String::new();
            loop {
                let c = buf.get_u8();
                if c == 0 {
                    break;
                }
                database.push(c as char);
            }
            login.database = Some(database);
        }

        if cap & CLIENT_PLUGIN_AUTH > 0 && buf.remaining() > 0 {
            let mut auth_plugin_name = String::new();
            loop {
                if buf.remaining() <= 0 {
                    break;
                }
                let c = buf.get_u8();
                if c == 0 {
                    break;
                }
                auth_plugin_name.push(c as char);
            }
            login.auth_plugin_name = Some(auth_plugin_name);
        }

        if cap & CLIENT_CONNECT_ATTRS > 0  {
            let mut attrs = HashMap::new();
            // discard len
            let totol_len = buf.get_u8();
            let mut read_len = 0;
            loop {
                if read_len >= totol_len  {
                    break;
                }
                let mut key = String::new();
                let len = buf.get_u8();
                for _ in 0..len {
                    key.push(buf.get_u8() as char);
                }

                read_len = read_len + len + 1;
                let mut value = String::new();

                let len = buf.get_u8();
                for _ in 0..len {
                    value.push(buf.get_u8() as char);
                }
                read_len = read_len + len + 1;
                attrs.insert(key, value);
            }
            login.attrs = attrs;
        }

        let zstd_compression_level = if cap & CLIENT_ZSTD_COMPRESSION_ALGORITHM > 0 {
            Some(buf.get_u8())
        } else {
            None
        };
        login.zstd_compression_level = zstd_compression_level;
        Some(login)
    }
}

#[cfg(test)]
mod test {
    use super::Login;
    #[test]
    pub fn test_mysql57_login() {
        env_logger::init();
        let packet_bytes = [
            0x85, 0xa6, 0xff, 0x00, 0x00, 0x00, 0x00, 0x40, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x14, 0xc8, 0x31, 0x92, 0xb6,
            0xe9, 0x77, 0xe4, 0xb5, 0xad, 0x29, 0xfb, 0x17, 0x68, 0x39, 0x87, 0xe8, 0xed, 0xfc,
            0x95, 0xce, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65,
            0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, 0x70, 0x03, 0x5f, 0x6f,
            0x73, 0x06, 0x44, 0x61, 0x72, 0x77, 0x69, 0x6e, 0x0c, 0x5f, 0x63, 0x6c, 0x69, 0x65,
            0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x0a, 0x6c, 0x69, 0x62, 0x6d, 0x61, 0x72,
            0x69, 0x61, 0x64, 0x62, 0x04, 0x5f, 0x70, 0x69, 0x64, 0x05, 0x35, 0x31, 0x37, 0x30,
            0x34, 0x0f, 0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x76, 0x65, 0x72, 0x73,
            0x69, 0x6f, 0x6e, 0x05, 0x33, 0x2e, 0x32, 0x2e, 0x33, 0x09, 0x5f, 0x70, 0x6c, 0x61,
            0x74, 0x66, 0x6f, 0x72, 0x6d, 0x05, 0x61, 0x72, 0x6d, 0x36, 0x34, 0x0c, 0x5f, 0x73,
            0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x68, 0x6f, 0x73, 0x74, 0x0e, 0x31, 0x39, 0x32,
            0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x30, 0x2e, 0x32, 0x32, 0x31,
        ];

        let login = Login::new(packet_bytes.to_vec());
        println!("{:?}", login);
        assert!(login.is_some());
        assert!(login.unwrap().username.is_some());


    }
}
