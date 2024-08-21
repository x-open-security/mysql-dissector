use crate::DBType;

#[derive(Clone, Debug)]
pub struct Payload(pub DBType, pub Vec<u8>);

impl Payload {
    pub fn new(db_type: DBType, payload: Vec<u8>) -> Payload {
        Payload(db_type, payload)
    }

    pub fn get_db_type(&self) -> DBType {
        self.0.clone()
    }

    pub fn get_payload(&self) -> Vec<u8> {
        self.1.clone()
    }
}

