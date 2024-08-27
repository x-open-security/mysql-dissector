use packets::DBType;
use crate::{SessionCtx, SessionPacket};

pub struct Session {
     session_ctx: SessionCtx,
}

impl Session {
    pub fn new(session_ctx: SessionCtx) -> Session {
        Session {
            session_ctx,
        }
    }

    pub async fn accept(&self, pkt: SessionPacket) {
        // do something
        match pkt.db {
            DBType::MySQL => {
                tokio::spawn(async  {

                });
            }

            _ => {
                // do something
            }
        }
    }
}