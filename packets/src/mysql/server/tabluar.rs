use std::io::Cursor;
use bytes::Buf;
use crate::mysql::common::{CLIENT_DEPRECATE_EOF, CLIENT_OPTIONAL_RESULTSET_METADATA};
use crate::mysql::common;
use crate::mysql::server::eof::EOFPacket;


pub struct LocalInline {
    pub packet_type: u8,
    pub payload: Option<Vec<u8>>,
}
pub enum MetadataType {
    ResultSetMetadataNone,
    ResultSetMetadataFull,
}

pub struct ColDef {
    pub catalog: Vec<u8>,
    pub schema: Vec<u8>,
    pub table: Vec<u8>,
    pub org_table: Vec<u8>,
    pub name: Vec<u8>,
    pub org_name: Vec<u8>,
    pub length_of_fixed_length_fields: u64, //  fixed 0x0c
    pub charset: u16,
    pub column_length: u32,
    pub column_type: u8,
    pub flags: u16,
    // 0x00 for integers and static strings
    // 0x1f for dynamic strings, double, float
    // 0x00 to 0x51 for decimals
    pub decimals: u8,
}



pub struct TextResult {
    pub metadata_follows: Option<MetadataType>,
    pub column_count: u64, // len_enc_int
    pub column_defs: Vec<ColDef>, // column_count * col_def
    // end of metadata
    // if (not capabilities & CLIENT_DEPRECATE_EOF) {
    pub eof: Option<EOFPacket>,
    // }

    // NULL is sent as 0xFB
    // everything else is converted to a string and is sent as string<lenenc>
    pub row: Vec<u8>,

    // if (error processing) {
    //     ERR_Packet	terminator	Error details
    // } else if capabilities & CLIENT_DEPRECATE_EOF {
    //     OK_Packet	terminator	All the execution details
    // } else {
    //     EOF_Packet	terminator	end of resultset marker
    // }

    pub terminator: u8,
    pub error_details: Option<Vec<u8>>,
    pub execution_details: Option<Vec<u8>>,
    pub eof_marker: Option<EOFPacket>,
}

impl TextResult {
    pub fn new(cap: u32, mut reader: Cursor<&[u8]>) -> Option<TextResult> {
        let metadata_follows = if cap & CLIENT_OPTIONAL_RESULTSET_METADATA > 0 {
            Some(MetadataType::ResultSetMetadataFull)
        } else {
            Some(MetadataType::ResultSetMetadataNone)
        };

        let column_count = common::read_len_enc_int(&mut reader).0;

        if column_count == 0 {
            return None;
        }

        if (cap & CLIENT_OPTIONAL_RESULTSET_METADATA) > 0 || (cap & CLIENT_OPTIONAL_RESULTSET_METADATA) > 0 {
            let mut column_defs = Vec::new();
            for _ in 0..column_count {
                let catalog = Vec::new();
                let schema = Vec::new();
                let table = Vec::new();
                let org_table = Vec::new();
                let name = Vec::new();
                let org_name = Vec::new();
                let length_of_fixed_length_fields = 0x0c;
                let charset = reader.get_u16_le();
                let column_length = reader.get_u32_le();
                let column_type = reader.get_u8();
                let flags = reader.get_u16_le();
                let decimals = reader.get_u8();
                column_defs.push(ColDef {
                    catalog,
                    schema,
                    table,
                    org_table,
                    name,
                    org_name,
                    length_of_fixed_length_fields,
                    charset,
                    column_length,
                    column_type,
                    flags,
                    decimals,
                });
            }
        }


        if cap & CLIENT_DEPRECATE_EOF <= 0  {
            let eof = EOFPacket::new(cap, &mut reader);
        }

        // discard the row
        loop {
            if reader.remaining() <= 0 {
                break;
            }

            let c = reader.get_u8();
            if c == 0xfb {
                break;
            }
        }

        // end of result sets
        let terminator = reader.get_u8();

        // If the SERVER_MORE_RESULTS_EXISTS flag is set in the last EOF_Packet / OK_Packet, another Text Result Set will follow.
        // todo handle more results exists
        match terminator {
            0xfe => {
                let mut error_details = Vec::new();
                loop {
                    let c = reader.get_u8();
                    if c == 0 {
                        break;
                    }
                    error_details.push(c);
                }
                Some(TextResult {
                    metadata_follows,
                    column_count,
                    column_defs: Vec::new(),
                    eof: None,
                    row: Vec::new(),
                    terminator,
                    error_details: Some(error_details),
                    execution_details: None,
                    eof_marker: None,
                })
            }
            0x00 => {
                let mut execution_details = Vec::new();
                loop {
                    let c = reader.get_u8();
                    if c == 0 {
                        break;
                    }
                    execution_details.push(c);
                }
                Some(TextResult {
                    metadata_follows,
                    column_count,
                    column_defs: Vec::new(),
                    eof: None,
                    row: Vec::new(),
                    terminator,
                    error_details: None,
                    execution_details: Some(execution_details),
                    eof_marker: None,
                })
            }
            0xff => {
                let eof_marker = EOFPacket::new(cap, &mut reader);
                Some(TextResult {
                    metadata_follows,
                    column_count,
                    column_defs: Vec::new(),
                    eof: None,
                    row: Vec::new(),
                    terminator,
                    error_details: None,
                    execution_details: None,
                    eof_marker: Some(eof_marker),
                })
            }
            _ => {
                None
            }
        }


        None
    }


}


pub struct Tabular {
    pub packet_type: u8,
    pub result_sets: Option<TextResult>,
    pub local_inlines: Option<Vec<LocalInline>>,
}

impl Tabular {
    pub fn new(cap: u32, mut reader: Cursor<&[u8]>) -> Option<Tabular> {
        loop {
            let packet_type = reader.get_u8();
            return match packet_type {
                0x00 => {
                    let result_sets = TextResult::new(cap, reader);
                    Some(Tabular {
                        packet_type,
                        result_sets,
                        local_inlines: None,
                    })
                }
                0xfe => {
                    let mut local_inlines = Vec::new();
                    loop {
                        let packet_type = reader.get_u8();
                        if packet_type == 0x00 {
                            break;
                        }
                        let payload_len = reader.get_u8();
                        let mut payload = vec![0; payload_len as usize];
                        reader.copy_to_slice(&mut payload);
                        local_inlines.push(LocalInline {
                            packet_type,
                            payload: Some(payload),
                        });
                    }
                    Some(Tabular {
                        packet_type,
                        result_sets: None,
                        local_inlines: Some(local_inlines),
                    })
                }
                _ => {
                    None
                }
            }
        }
    }
}





#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    #[test]
    pub fn test_text_results_tabular() {
        let packet_bytes:&[u8]= &[
            0x01, 0x00, 0x00, 0x01, 0x01, 0x35, 0x00, 0x00,
            0x02, 0x03, 0x64, 0x65, 0x66, 0x00, 0x00, 0x00,
            0x1f, 0x40, 0x40, 0x73, 0x65, 0x73, 0x73, 0x69,
            0x6f, 0x6e, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73,
            0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69,
            0x73, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e,
            0x00, 0x0c, 0x2d, 0x00, 0x3c, 0x00, 0x00, 0x00,
            0xfd, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x03, 0x0f, 0x52, 0x45, 0x50, 0x45, 0x41,
            0x54, 0x41, 0x42, 0x4c, 0x45, 0x2d, 0x52, 0x45,
            0x41, 0x44, 0x07, 0x00, 0x00, 0x04, 0xfe, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00
        ];

        let mut reader = Cursor::new(packet_bytes);
        let tabular = Tabular::new(16754309, reader);

    }


    ///! Test for local file tabular
    #[test]
    pub fn test_local_file_tabular() {

    }
}