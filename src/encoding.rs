use std::mem::size_of;

use anyhow::Result;
use log::{log_enabled, trace, Level};
use openssl::bn::BigNumRef;

use crate::{crypto::generate_random_array, types::MessageType};

pub const PACKET_LENGTH_SIZE: usize = size_of::<u32>();
pub const PADDING_LENGTH_SIZE: usize = size_of::<u8>();
pub const STRING_LENGTH_SIZE: usize = size_of::<u32>();

const MIN_PADDING: u8 = 4;

pub struct PacketBuilder {
    payload: Vec<u8>,
}

#[allow(dead_code)]
impl PacketBuilder {
    pub fn new(message_type: MessageType) -> Self {
        PacketBuilder {
            payload: vec![message_type as u8],
        }
    }

    // RFC 4253 § 6
    pub fn build(self) -> Result<Vec<u8>> {
        trace!("-- BEGIN PACKET ENCODING --");

        // TODO:
        const CIPHER_BLOCK_SIZE: usize = 8;

        let p = PACKET_LENGTH_SIZE + PADDING_LENGTH_SIZE + self.payload.len();
        let padding_length = u8::max(
            (CIPHER_BLOCK_SIZE - (p % CIPHER_BLOCK_SIZE)) as u8,
            MIN_PADDING,
        );
        let packet_length: u32 =
            (PADDING_LENGTH_SIZE + self.payload.len() + padding_length as usize) as u32;
        let random_padding = generate_random_array(padding_length.into())?;

        trace!("packet_length = {} bytes", packet_length);
        trace!("padding_length = {} bytes", padding_length);
        if log_enabled!(Level::Trace) {
            trace!("payload = {:?}", String::from_utf8_lossy(&self.payload));
        }
        trace!("random_padding = {:?}", random_padding);

        let mut packet = Vec::<u8>::with_capacity(
            PACKET_LENGTH_SIZE + PADDING_LENGTH_SIZE + self.payload.len() + padding_length as usize,
        );
        packet.extend_from_slice(&encode_u32(packet_length));
        packet.push(padding_length);
        packet.extend_from_slice(&self.payload);
        packet.extend(random_padding);
        // TODO: mac

        trace!("-- END PACKET ENCODING --");
        Ok(packet)
    }

    /// # Returns
    /// `(payload, packet)`
    pub fn build_get_payload(self) -> Result<(Vec<u8>, Vec<u8>)> {
        let payload = self.payload.clone();
        let packet = self.build()?;

        Ok((payload, packet))
    }

    pub fn write_byte(mut self, value: u8) -> Self {
        self.payload.push(value);
        self
    }

    pub fn write_bytes(mut self, data: &[u8]) -> Self {
        self.payload.extend(data);
        self
    }

    pub fn write_bool(mut self, value: bool) -> Self {
        self.payload.push(encode_bool(value));
        self
    }

    pub fn write_u32(mut self, value: u32) -> Self {
        self.payload.extend(encode_u32(value));
        self
    }

    // RFC 4251 § 5
    pub fn write_name_list(mut self, names: &[String]) -> Self {
        self.payload.extend(encode_name_list(names));
        self
    }

    // RFC 4251 § 5
    /// **IMPORTANT**: Not for regular text, but for `string` from [RFC 4251 § 5](https://datatracker.ietf.org/doc/html/rfc4251#section-5). For encoding text convert it to binary format and use `write_bytes`.
    pub fn write_string(mut self, data: &[u8]) -> Self {
        self.payload.extend(encode_string(data));
        self
    }

    // RFC 4251 § 5
    pub fn write_mpint(mut self, data: &BigNumRef) -> Self {
        self.payload.extend(encode_mpint(data));
        self
    }
    pub fn write_mpint_pad(mut self, data: &BigNumRef) -> Self {
        self.payload.extend(encode_mpint_pad(data));
        self
    }
}

pub fn encode_bool(value: bool) -> u8 {
    match value {
        false => 0,
        true => 1,
    }
}
pub fn encode_u32(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

pub fn encode_name_list(names: &[String]) -> Vec<u8> {
    trace!("-- BEGIN NAME-LIST ENCODING --");

    let joined = names.join(",");
    trace!("joined = {:?}", joined);

    let payload = joined.as_bytes();

    let mut name_list = Vec::<u8>::new();
    name_list.extend_from_slice(&encode_u32(payload.len() as u32));
    name_list.extend_from_slice(payload);
    trace!("name_list = {:?}", name_list);

    trace!("-- END NAME-LIST ENCODING --");
    name_list
}

pub fn encode_string(data: &[u8]) -> Vec<u8> {
    trace!("-- BEGIN STRING ENCODING --");
    trace!("length = {}", data.len());
    trace!("data = {:?}", data);

    let mut string = Vec::with_capacity(STRING_LENGTH_SIZE + data.len());
    let length_bytes = encode_u32(data.len() as u32);
    string.extend_from_slice(&length_bytes);
    string.extend_from_slice(data);

    trace!("string = {:?}", string);
    if log_enabled!(Level::Trace) {
        trace!("string = {:?}", String::from_utf8_lossy(&string));
    }

    trace!("-- END STRING ENCODING --");
    string
}

pub fn encode_mpint(data: &BigNumRef) -> Vec<u8> {
    encode_mpint_internal(data, false)
}
pub fn encode_mpint_pad(data: &BigNumRef) -> Vec<u8> {
    encode_mpint_internal(data, true)
}
fn encode_mpint_internal(data: &BigNumRef, pad: bool) -> Vec<u8> {
    trace!("-- BEGIN MPINT ENCODING --");

    let mut bin = data.to_vec();
    trace!("data = {:?}, length = {}", bin, bin.len());

    if !pad {
        if !bin.is_empty() && (bin[0] & 0b1000_0000) != 0 {
            trace!("Adding a zero byte to the beginning of mpint");
            bin.insert(0, 0);
        }
    } else {
        trace!("Adding a zero byte to the beginning of mpint");
        bin.insert(0, 0);
    }

    let mpint = encode_string(&bin);
    trace!("-- END MPINT ENCODING --");
    mpint
}
