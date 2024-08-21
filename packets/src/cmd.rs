use pnet_macros_support::packet::PrimitiveValues;
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct Command(pub u8);

impl Command {
    pub fn new(field_val: u8) -> Command {
        Command(field_val)
    }
}

impl PrimitiveValues for Command {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}
