use std::error::Error;
use crate::cmd::Command;

pub trait Protocol {
    fn get_payload(&self) -> Vec<u8>;
    fn get_cmd(&self) -> Command;

    fn get_seq(&self) -> u8;

    fn parse(&self) -> Result<(), Box<dyn Error>>;
}
