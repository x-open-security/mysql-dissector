use pnet_macros_support::packet::PrimitiveValues;
use std::error::Error;

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

