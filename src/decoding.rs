use std::{
    io::{BufReader, Read},
    net::TcpStream,
};

use anyhow::{anyhow, Context, Result};
use log::{log_enabled, trace, Level};
use num_traits::FromPrimitive;

use crate::{
    encoding::{PACKET_LENGTH_SIZE, STRING_LENGTH_SIZE},
    types::MessageType,
};

#[derive(Debug)]
pub struct DecodedPacket {
    payload: Vec<u8>,
    entire_packet_length: u32,
}

impl DecodedPacket {
    pub fn message_type(&self) -> Result<MessageType> {
        if self.payload.is_empty() {
            return Err(anyhow!("Payload is empty"));
        }

        let message_type = u8_to_MessageType(self.payload[0])?;
        Ok(message_type)
    }

    /// Returns the payload without the message type
    pub fn payload(&self) -> Vec<u8> {
        let without_msg_type = &self.payload[1..];
        without_msg_type.to_vec()
    }

    pub fn payload_with_msg_type(&self) -> &Vec<u8> {
        &self.payload
    }

    pub fn entire_packet_length(&self) -> u32 {
        self.entire_packet_length
    }
}

// RFC 4253 § 6
pub fn decode_packet(stream: &TcpStream) -> Result<DecodedPacket> {
    trace!("-- BEGIN PACKET DECODING --");

    let mut reader = BufReader::new(stream);

    let mut packet_length_bytes = [0u8; PACKET_LENGTH_SIZE];
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

    let bytes_left = packet_length - 1 - n1 as u32 - padding_length as u32; // TODO: mac
    if bytes_left != 0 {
        return Err(anyhow!(
            "Didn't decode entire packet, {} bytes left",
            bytes_left
        ));
    }

    trace!("-- END PACKET DECODING --");
    Ok(DecodedPacket {
        payload,
        entire_packet_length: packet_length + PACKET_LENGTH_SIZE as u32, // TODO: mac
    })
}

// RFC 4251 § 5
/// - `iter` - iterator where `iter.next()` will return the first byte of the name-list
pub fn decode_name_list(iter: &mut dyn Iterator<Item = u8>) -> Result<Vec<String>> {
    trace!("-- BEGIN NAME-LIST DECODING --");

    let length_bytes = iter.take(PACKET_LENGTH_SIZE).collect::<Vec<u8>>();
    let length = u8_array_to_u32(length_bytes.as_slice())?;
    trace!("length = {} bytes", length);

    let value_bytes = iter.take(length as usize).collect::<Vec<u8>>();
    let value = String::from_utf8(value_bytes).context("Failed to decode name-list to string")?;
    trace!("value = {}", value);

    let name_list = value.split(',').map(String::from).collect();
    trace!("name_list = {:?}", name_list);
    trace!("-- END NAME-LIST DECODING --");

    Ok(name_list)
}

pub fn decode_string(iter: &mut dyn Iterator<Item = u8>) -> Result<Vec<u8>> {
    trace!("-- BEGIN STRING DECODING --");

    let length_bytes = iter.take(STRING_LENGTH_SIZE).collect::<Vec<u8>>();
    let length = u8_array_to_u32(&length_bytes)?;
    trace!("length = {}", length);

    let string = iter.take(length as usize).collect();
    trace!("string = {:?}", string);

    trace!("-- END STRING DECODING --");
    Ok(string)
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

pub fn packet_too_short<T>(var_name: &str) -> Result<T> {
    Err(anyhow!(
        "Packet too short - '{}' could not be read",
        var_name
    ))
}
