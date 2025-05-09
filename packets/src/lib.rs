use pnet_macros_support::packet::PrimitiveValues;
use std::any::Any;
use std::error::Error;

pub mod mysql;

#[derive(Debug, Clone, Default)]
pub struct Command(pub u8);

impl From<u8> for Command {
    fn from(v: u8) -> Self {
        Command(v)
    }
}

#[derive(Clone, Debug)]
pub enum DBType {
    MySQL,
    Unknown,
}

impl std::fmt::Display for DBType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            DBType::MySQL => write!(f, "MySQL"),
            DBType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::str::FromStr for DBType {
    type Err = Box<dyn Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "MySQL" => Ok(DBType::MySQL),
            "Unknown" => Ok(DBType::Unknown),
            _ => Err("Invalid DBType".into()),
        }
    }
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
pub trait DBPacket: Send + Sync + CloneBoxDBPacket {
    fn db_type(&self) -> DBType;
    fn get_command(&self) -> Command;
    fn get_payload(&self) -> Vec<u8>;
    fn get_seq(&self) -> u8;
    fn get_len(&self) -> u32;
    fn as_any(&self) -> &dyn Any;
    fn is_request(&self) -> bool;
}

pub trait CloneBoxDBPacket {
    fn clone_box(&self) -> Box<dyn DBPacket>;
}

impl<T> CloneBoxDBPacket for T
where
    T: 'static + DBPacket + Clone,
{
    fn clone_box(&self) -> Box<dyn DBPacket> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn DBPacket> {
    fn clone(&self) -> Box<dyn DBPacket> {
        self.clone_box()
    }
}



