mod general_response;
pub mod greeting;

#[derive(Debug, Default)]
enum SessionTrackType {
    #[default]
    SessionTrackSchema,
    SessionTrackStateChange,
    SessionTrackGtids,
    SessionTrackTransactionCharacteristics,
    SessionTrackTransactionState,
}

impl From<u8> for SessionTrackType {
    fn from(v: u8) -> Self {
        match v {
            0x1 => SessionTrackType::SessionTrackSchema,
            0x2 => SessionTrackType::SessionTrackStateChange,
            0x3 => SessionTrackType::SessionTrackGtids,
            0x4 => SessionTrackType::SessionTrackTransactionCharacteristics,
            0x5 => SessionTrackType::SessionTrackTransactionState,
            _ => SessionTrackType::SessionTrackSchema,
        }
    }
}