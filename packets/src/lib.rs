pub mod mysql;

trait Decoder {
    fn decode(&self, data: &[u8]) -> Result<(), String>;
}
