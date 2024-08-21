use pnet_macros_support::packet::PrimitiveValues;
use std::error::Error;
use cmd::Command;
pub mod mysql;
pub mod cmd;
pub mod proto;
pub mod payload;


#[derive(Debug, Clone)]
pub struct Parser {
    db_type: DBType,
    payload: Vec<u8>,
}

impl Parser {
    pub fn new(db_type: DBType, payload: Vec<u8>) -> Parser {
        Parser { db_type, payload }
    }

    pub fn parse(&self) -> Result<(), Box<dyn Error>> {
        match self.db_type {
            DBType::MySQL => {
                let mysql_pkt = mysql::new_mysql_packet(&self.payload);
                if mysql_pkt.is_none() {
                    return Err("Invalid mysql packet".into());
                }
                let mysql_pkt = mysql_pkt.unwrap();
                println!("{:?}", mysql_pkt);
            }
            DBType::Unknown => {
                return Err("Unknown db type".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum DBType {
    MySQL,
    Unknown,
}


impl PrimitiveValues for DBType {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        match *self {
            DBType::MySQL => (0,),
            DBType::Unknown => (1,),
        }
    }
}

// impl ProtocolPkt {
//     pub fn new(db_type: DBType, payload: &Vec<u8>) -> Option<ProtocolPkt> {
//         if payload.len() < 5 {
//             return None;
//         }
//         // mysql protocol header
//         let len = payload[0] as u32 | ((payload[1] as u32) << 8) | ((payload[2] as u32) << 16);
//         let seq = payload[3];
//         let cmd = Command::new(payload[4]);
//
//         Some(ProtocolPkt {
//             len,
//             seq,
//             cmd,
//             payload: Payload::new(db_type, payload[5..].to_vec()),
//         })
//     }
//
// }