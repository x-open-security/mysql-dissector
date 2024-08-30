use crate::mysql::common;
use crate::mysql::common::{
    CLIENT_PROTOCOL_41, CLIENT_SESSION_TRACK, CLIENT_TRANSACTIONS, SERVER_SESSION_STATE_CHANGED,
};
use crate::mysql::server::SessionTrackType;
use crate::Command;
use bytes::Buf;
use std::io::Cursor;

#[derive(Debug, Default)]
pub struct OKPacket {
    pub cmd: Command,
    pub affected_rows: u64,
    pub last_insert_id: u64,
    pub status_flags: Option<u16>,
    pub warnings: Option<u16>,
    pub session_track_info: Option<SessionTrackInfo>,
}

#[derive(Debug, Default)]
pub struct SessionTrackInfo {
    pub r#type: SessionTrackType,
    pub info: String,
    pub schema_change_info: Option<String>,
}

impl OKPacket {
    pub fn new(cap: u32, payload: Vec<u8>) -> Option<Self> {
        let mut reader = Cursor::new(payload);
        let mut ok_pkt = OKPacket::default();
        let cmd = Command::from(reader.get_u8());
        ok_pkt.cmd = cmd;

        let affected_rows = common::read_len_enc_int(&mut reader).0;
        let last_insert_id = common::read_len_enc_int(&mut reader).0;
        ok_pkt.affected_rows = affected_rows;
        ok_pkt.last_insert_id = last_insert_id;

        if cap & CLIENT_PROTOCOL_41 > 0 {
            let status_flags = Some(reader.get_u16_le());
            let warnings = Some(reader.get_u16_le());
            ok_pkt.status_flags = status_flags;
            ok_pkt.warnings = warnings;
        } else if cap & CLIENT_TRANSACTIONS > 0 {
            let status_flags = Some(reader.get_u16_le());
            ok_pkt.status_flags = status_flags;
        }

        if reader.remaining() <= 0 {
            return Some(ok_pkt);
        }

        if reader.remaining() <= 0 {
            return Some(ok_pkt);
        }
        let unknown = reader.get_u8(); // skip 0x00
        if unknown != 0 {
            return None;
        }

        if SERVER_SESSION_STATE_CHANGED & ok_pkt.status_flags? > 0 {
            reader.get_u8();
            let session_track_info_type = reader.get_u8();
            reader.get_u8();
            match SessionTrackType::from(session_track_info_type) {
                SessionTrackType::SessionTrackSchema => {
                    let schema_change_length = reader.get_u8();
                    if schema_change_length > reader.remaining() as u8 {
                        return Some(ok_pkt);
                    }

                    let schema_change_info = String::from_utf8_lossy(
                        &reader.get_ref()[reader.position() as usize
                            ..reader.position() as usize + schema_change_length as usize],
                    )
                    .to_string();
                    reader.set_position(reader.position() + schema_change_length as u64);
                    ok_pkt.session_track_info = Some(SessionTrackInfo {
                        r#type: SessionTrackType::SessionTrackSchema,
                        info: "".to_string(),
                        schema_change_info: Some(schema_change_info),
                    });
                }
                _ => {
                    // nothing to do
                }
            }
        } else {
            let session_track_info = common::read_len_enc_str(&mut reader).0;
            ok_pkt.session_track_info = Some(SessionTrackInfo {
                r#type: SessionTrackType::None,
                info: session_track_info,
                schema_change_info: None,
            });
        }

        Some(ok_pkt)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ok_packet_without_session_track() {
        let payload = vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        let ok_pkt = OKPacket::new(16754309, payload).unwrap();
        assert_eq!(ok_pkt.affected_rows, 0);
        assert_eq!(ok_pkt.last_insert_id, 0);
        assert_eq!(ok_pkt.status_flags, Some(2));
        println!("{:?}", ok_pkt)
    }

    #[test]
    fn test_ok_packet_with_session_track() {
        let payload = vec![
            0x00, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00, 0x15, 0x01, 0x13, 0x12, 0x69, 0x6e,
            0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x73, 0x63, 0x68, 0x65,
            0x6d, 0x61,
        ];
        let ok_pkt = OKPacket::new(16754309, payload).unwrap();

        assert_eq!(ok_pkt.affected_rows, 0);
        assert_eq!(ok_pkt.last_insert_id, 0);
        assert_eq!(ok_pkt.status_flags, Some(0x4002));
        println!("{:?}", ok_pkt);
    }
}
