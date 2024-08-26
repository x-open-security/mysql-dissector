pub struct Handshake {
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

