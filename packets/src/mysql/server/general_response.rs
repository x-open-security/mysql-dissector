use crate::Command;
use bytes::Buf;
use std::io::Cursor;
use crate::mysql::common;
use crate::mysql::common::{CLIENT_PROTOCOL_41, CLIENT_SESSION_TRACK, SERVER_SESSION_STATE_CHANGED};

#[derive(Debug, Default)]
pub struct OKPacket {
    pub cmd: Command,
    pub affected_rows: u64,
    pub last_insert_id: u64,
    pub status_flags: Option<u16>,
    pub warnings: Option<u16>,
    pub session_state_change: Option<SessionStateChange>,
    pub session_track_info: Option<SessionTrackInfo>,
}

#[derive(Debug, Default)]
pub struct SessionTrackInfo {
    pub info: String,
}

#[derive(Debug, Default)]
pub struct SessionStateChange {
    pub info: String,
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


        if cap & CLIENT_PROTOCOL_41 >0 {
            let status_flags = Some(reader.get_u16_le());
            let warnings = Some(reader.get_u16_le());
            ok_pkt.status_flags = status_flags;
            ok_pkt.warnings = warnings;
        }

        if reader.remaining() <= 0 {
            return Some(ok_pkt);
        }
        if cap & CLIENT_SESSION_TRACK > 0 {
            let session_state_change = SessionStateChange {
                info: common::read_len_enc_str(&mut reader).0,
            };
            ok_pkt.session_state_change = Some(session_state_change);
            if ok_pkt.status_flags.is_some() && (ok_pkt.status_flags? & SERVER_SESSION_STATE_CHANGED  > 0 ){
                let session_track_info = SessionTrackInfo {
                    info: common::read_len_enc_str(&mut reader).0,
                };
                ok_pkt.session_track_info = Some(session_track_info);
            }
        } else {
            let info =  common::read_len_enc_str(&mut reader).0;

            let session_track_info = SessionTrackInfo {
                info,
            };

            ok_pkt.session_track_info = Some(session_track_info);
        }


        Some(ok_pkt)
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ok_packet() {
        let payload = vec![
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00
        ];
        let ok_pkt = OKPacket::new(16754309, payload).unwrap();
        assert_eq!(ok_pkt.affected_rows, 0);
        assert_eq!(ok_pkt.last_insert_id, 0);
        assert_eq!(ok_pkt.status_flags, Some(2));
    }
}
