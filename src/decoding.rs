use std::{
    io::{BufReader, Read},
    net::TcpStream,
};

use anyhow::{anyhow, Context, Result};
use log::{log_enabled, trace, Level};
use num_traits::FromPrimitive;

use crate::types::MessageType;

// RFC 4253 § 6
pub fn decode_packet(stream: &TcpStream) -> Result<Vec<u8>> {
    trace!("-- BEGIN PACKET DECODING --");

    let mut reader = BufReader::new(stream);

    let mut packet_length_bytes = [0u8; 4];
    reader
        .read_exact(&mut packet_length_bytes)
        .context("Failed reading packet_length")?;
    let packet_length = u8_array_to_u32(&packet_length_bytes)?;
    trace!("packet_length = {} bytes", packet_length);

    let mut padding_length_bytes = [0u8; 1];
    reader
        .read_exact(&mut padding_length_bytes)
        .context("Failed reading padding_length")?;
    let padding_length = padding_length_bytes[0];
    trace!("padding_length = {} bytes", padding_length);

    let n1: u32 = packet_length - (padding_length as u32) - 1;
    let mut payload = vec![0u8; n1 as usize];
    reader
        .read_exact(&mut payload)
        .context("Failed reading payload")?;

    if log_enabled!(Level::Trace) {
        trace!("payload = {:?}", String::from_utf8_lossy(&payload));
    }

    let mut random_padding = vec![0u8; padding_length as usize];
    reader
        .read_exact(&mut random_padding)
        .context("Failed reading random padding")?;
    trace!("random_padding = {:?}", random_padding);

    // TODO: mac (initially no message authentication has been negotiated, so mac isn't added)

    let bytes_left = packet_length - 1 - payload.len() as u32 - padding_length as u32;
    if bytes_left != 0 {
        return Err(anyhow!(
            "Didn't decode entire packet, {} bytes left",
            bytes_left
        ));
    }

    trace!("-- END PACKET DECODING --");
    Ok(payload)
}

// RFC 4251 § 5
/// * `iter` - iterator where `iter.next()` will return the first byte of the name-list
pub fn decode_name_list(iter: &mut dyn Iterator<Item = u8>) -> Result<Vec<String>> {
    trace!("-- BEGIN NAME-LIST DECODING --");

    let length_bytes = iter.take(4).collect::<Vec<u8>>();
    let length = u8_array_to_u32(length_bytes.as_slice())?;
    trace!("length = {} bytes", length);

    let value_bytes = iter.take(length as usize).collect::<Vec<u8>>();
    let value = String::from_utf8(value_bytes).context("Failed to decode name-list to string")?;
    trace!("value = {}", value);

    let name_list = value.split(',').map(String::from).collect::<Vec<String>>();
    trace!("name_list = {:?}", name_list);
    trace!("-- END NAME-LIST DECODING --");

    Ok(name_list)
}

pub fn u8_array_to_u32(array: &[u8]) -> Result<u32> {
    if array.len() != 4 {
        return Err(anyhow!(
            "Cannot convert u8 array of length {} to u32",
            array.len()
        ));
    }

    Ok(u32::from_be_bytes([array[0], array[1], array[2], array[3]]))
}

pub fn u8_to_bool(value: u8) -> Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(anyhow!("Cannot convert u8 of value {} to bool", value)),
    }
}

#[allow(non_snake_case)]
pub fn u8_to_MessageType(value: u8) -> Result<MessageType> {
    MessageType::from_u8(value).context(format!("Failed to cast {} into MessageType", value))
}
