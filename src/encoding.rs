use std::mem::size_of;

use anyhow::Result;
use log::{log_enabled, trace, Level};

use crate::crypto::random_array;

pub const PACKET_LENGTH_SIZE: usize = size_of::<u32>();
pub const PADDING_LENGTH_SIZE: usize = size_of::<u8>();
const MIN_PADDING: u8 = 4;

// RFC 4253 § 6
pub fn encode_packet(payload: &[u8]) -> Result<Vec<u8>> {
    trace!("-- BEGIN PACKET ENCODING --");

    // TODO:
    const CIPHER_BLOCK_SIZE: usize = 8;

    let p = PACKET_LENGTH_SIZE + PADDING_LENGTH_SIZE + payload.len();
    let padding_length = u8::max(
        (CIPHER_BLOCK_SIZE - (p % CIPHER_BLOCK_SIZE)) as u8,
        MIN_PADDING,
    );
    let packet_length: u32 = (PADDING_LENGTH_SIZE + payload.len() + padding_length as usize) as u32;
    let random_padding = random_array(padding_length.into())?;

    trace!("packet_length = {} bytes", packet_length);
    trace!("padding_length = {} bytes", padding_length);
    if log_enabled!(Level::Trace) {
        trace!(
            "payload = {:?}, length = {}",
            String::from_utf8_lossy(payload),
            payload.len()
        );
    }
    trace!("random_padding = {:?}", random_padding);

    let mut packet = Vec::<u8>::with_capacity(
        PACKET_LENGTH_SIZE + PADDING_LENGTH_SIZE + payload.len() + padding_length as usize,
    );
    packet.extend_from_slice(&u32_to_u8_array(packet_length));
    packet.push(padding_length);
    packet.extend_from_slice(payload);
    packet.extend(random_padding);
    // TODO: mac

    trace!("-- END PACKET ENCODING --");
    Ok(packet)
}

// RFC 4251 § 5
pub fn encode_name_list(names: &[String]) -> Vec<u8> {
    trace!("-- BEGIN NAME-LIST ENCODING --");

    let joined = names.join(",");
    trace!("joined = {:?}", joined);

    let payload = joined.as_bytes();

    let mut name_list = Vec::<u8>::new();
    name_list.extend_from_slice(&u32_to_u8_array(payload.len() as u32));
    name_list.extend_from_slice(payload);
    trace!("name_list = {:?}", name_list);

    trace!("-- END NAME-LIST ENCODING --");
    name_list
}

pub fn u32_to_u8_array(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

pub fn bool_to_u8(value: bool) -> u8 {
    match value {
        false => 0,
        true => 1,
    }
}
