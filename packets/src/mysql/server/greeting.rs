use bytes::Buf;
use log::error;

use std::io::Cursor;

#[derive(Debug)]
pub struct Greeting {
    pub protocol_version: u8,
    pub server_version: String,
    pub connection_id: u32,
    pub auth_plugin_data: Vec<u8>, // terminated by 0x00
    pub capability_flags: u16,
    pub server_language: u8,
    pub status_flags: u16,
    pub extended_capability_flags: u16,
    pub auth_plugin_len: u8,
    pub unused: [u8; 10],
    pub auth_plugin_data_2: Vec<u8>, // terminated by 0x00
    pub auth_plugin_name: String,    // terminated by 0x00
}

impl Greeting {
    pub fn new(payload: Vec<u8>) -> Option<Self> {
        let mut reader = Cursor::new(payload);

        let protocol_version = reader.get_u8();

        let mut server_version = String::new();
        loop {
            let c = reader.get_u8();
            if c == 0 {
                break;
            }
            server_version.push(c as char);
        }

        let connection_id = reader.get_u32_le();

        let mut auth_plugin_data = Vec::new();
        loop {
            let c = reader.get_u8();
            if c == 0 {
                break;
            }
            auth_plugin_data.push(c);
        }

        let capability_flags = reader.get_u16_le();
        let server_language = reader.get_u8();
        let status_flags = reader.get_u16_le();
        let extended_capability_flags = reader.get_u16_le();
        let auth_plugin_len = reader.get_u8();
        let mut unused = [0; 10];
        for i in 0..10 {
            unused[i] = reader.get_u8();
            if unused[i] != 0 {
                error!("mysql server greeting unused field is not 0");
                return None;
            }
        }

        let mut auth_plugin_data_2 = Vec::new();
        loop {
            let c = reader.get_u8();
            if c == 0 {
                break;
            }
            auth_plugin_data_2.push(c);
        }

        let mut auth_plugin_name = String::new();
        loop {
            let c = reader.get_u8();
            if c == 0 {
                break;
            }
            auth_plugin_name.push(c as char);
        }

        Some(Greeting {
            protocol_version,
            server_version,
            connection_id,
            auth_plugin_data,
            capability_flags,
            server_language,
            status_flags,
            extended_capability_flags,
            auth_plugin_len,
            unused,
            auth_plugin_data_2,
            auth_plugin_name,
        })
    }
}

#[cfg(test)]
mod test {
    #[test]
    pub fn test_mysql57_greeting() {
        use super::Greeting;
        use std::io::Cursor;

        let payload = [
            0x0a, 0x35, 0x2e, 0x37, 0x2e, 0x34, 0x34, 0x00, 0xee, 0x08, 0x00, 0x00, 0x65, 0x6d,
            0x50, 0x7f, 0x1f, 0x19, 0x2c, 0x32, 0x00, 0xff, 0xff, 0x08, 0x02, 0x00, 0xff, 0xc1,
            0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x67, 0x1d,
            0x39, 0x40, 0x1b, 0x6c, 0x7a, 0x66, 0x2f, 0x6a, 0x62, 0x00, 0x6d, 0x79, 0x73, 0x71,
            0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77,
            0x6f, 0x72, 0x64, 0x00,
        ];

        let reader = Cursor::new(payload);
        let greeting = Greeting::new(reader.get_ref().to_vec()).unwrap();

        let expected = Greeting {
            protocol_version: 10,
            server_version: "5.7.44".to_string(),
            connection_id: 2286,
            auth_plugin_data: vec![101, 109, 80, 127, 31, 25, 44, 50],
            capability_flags: 65535,
            server_language: 8,
            status_flags: 2,
            extended_capability_flags: 49663,
            auth_plugin_len: 21,
            unused: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            auth_plugin_data_2: vec![37, 103, 29, 57, 64, 27, 108, 122, 102, 47, 106, 98],
            auth_plugin_name: "mysql_native_password".to_string(),
        };
        assert_eq!(greeting.protocol_version, expected.protocol_version);
    }
}
