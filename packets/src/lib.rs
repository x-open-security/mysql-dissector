use pnet_macros_support::packet::PrimitiveValues;
use std::error::Error;
use std::any::Any;

pub mod mysql;

#[derive(Debug, Clone)]
pub struct Command(pub u8);

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


// mark send packet
pub trait DBPacket: Send {
    fn db_type(&self) -> DBType;
    fn get_command(&self) -> Command;
    fn get_payload(&self) -> Vec<u8>;
    fn get_seq(&self) -> u8;
    fn get_len(&self) -> u32;
    fn as_any(&self) -> &dyn Any;
}

impl std::fmt::Debug for dyn DBPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DBPacket")
    }
}
