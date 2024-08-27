pub struct Login {
    pub protocol_version: u8,
    pub server_version: String,
    pub connection_id: u32,
    pub auth_plugin_data: Vec<u8>,
    pub capability_flags: u16,
    pub character_set: u8,
    pub status_flags: u16,
    pub auth_plugin_name: String,
    pub username: Option<String>,
    pub database: Option<String>,
}

impl Login {
    pub fn new(payload: Vec<u8>) -> Option<Self> {
        let mut reader = Cursor::new(payload);

        let protocol_version = reader.get_u8();

        let mut server_version = String::new();
        while let c = reader.get_u8() {
            if c == 0 {
                break;
            }
            server_version.push(c as char);
        }

        let connection_id = reader.get_u32_le();

        let mut auth_plugin_data = Vec::new();
        while let c = reader.get_u8() {
            if c == 0 {
                break;
            }
            auth_plugin_data.push(c);
        }

        let capability_flags = reader.get_u16_le();
        let character_set = reader.get_u8();
        let status_flags = reader.get_u16_le();
        let unused = reader.get_u16_le();
        let auth_plugin_len = reader.get_u8();
        let mut unused = [0; 10];
        for i in 0..10 {
            unused[i] = reader.get_u8();
            if unused[i] != 0 {
                error!("mysql login unused field is not 0");
                return None;
            }
        }

        let mut auth_plugin_data_2 = Vec::new();
        while let c = reader.get_u8() {
            if c == 0 {
                break;
            }
            auth_plugin_data_2.push(c);
        }

        let mut auth_plugin_name = String::new();
        while let c = reader.get_u8() {
            if c == 0 {
                break;
            }
            auth_plugin_name.push(c as char);
        }

        Some(Login {
            protocol_version,
            server_version,
            connection_id,
            auth_plugin_data,
            capability_flags,
            character_set,
            status_flags,
            auth_plugin_name,
            username: None,
            database: None,
        })
    }
}