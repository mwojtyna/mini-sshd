use std::mem::size_of;

use anyhow::Result;
use log::{debug, log_enabled, trace, Level};
use num_traits::FromPrimitive;
use openssl::{bn::BigNumRef, ecdsa::EcdsaSigRef};

use crate::{
    crypto::Crypto,
    session::{algorithm_negotiation::Algorithm, Session},
    types::{HostKeyAlgorithmDetails, MessageType},
};

pub const PACKET_LENGTH_SIZE: usize = size_of::<u32>();
pub const PADDING_LENGTH_SIZE: usize = size_of::<u8>();
pub const STRING_LENGTH_SIZE: usize = size_of::<u32>();

const MIN_PADDING: u8 = 4;

pub struct PacketBuilder<'a> {
    payload: Vec<u8>,
    session: &'a Session<'a>,
}

#[allow(dead_code)]
impl<'a> PacketBuilder<'a> {
    pub fn new(message_type: MessageType, session: &'a Session<'a>) -> Self {
        PacketBuilder {
            payload: vec![message_type as u8],
            session,
        }
    }

    // RFC 4253 § 6
    pub fn build(self) -> Result<Vec<u8>> {
        trace!(
            "-- BEGIN PACKET ENCODING{} --",
            if self.session.kex().finished {
                " (ENCRYPTED)"
            } else {
                ""
            }
        );

        let block_size = if self.session.kex().finished {
            self.session
                .algorithms()
                .encryption_algorithms_server_to_client
                .details
                .block_size
        } else {
            8
        };

        let p = PACKET_LENGTH_SIZE + PADDING_LENGTH_SIZE + self.payload.len();
        let mut padding_length = (block_size - (p % block_size)) as u8;
        if padding_length < MIN_PADDING {
            padding_length += block_size as u8;
        }

        let packet_length: u32 =
            (PADDING_LENGTH_SIZE + self.payload.len() + padding_length as usize) as u32;
        let random_padding = Crypto::generate_random_array(padding_length.into())?;

        trace!("packet_length = {} bytes", packet_length);
        trace!("padding_length = {} bytes", padding_length);
        if log_enabled!(Level::Trace) {
            trace!("payload = {:?}", String::from_utf8_lossy(&self.payload));
        }
        trace!("random_padding = {:02x?}", random_padding);

        let mut packet = Vec::<u8>::with_capacity(
            PACKET_LENGTH_SIZE + PADDING_LENGTH_SIZE + self.payload.len() + padding_length as usize,
        );
        packet.extend_from_slice(&encode_u32(packet_length));
        packet.push(padding_length);
        packet.extend_from_slice(&self.payload);
        packet.extend(random_padding);

        if self.session.kex().finished {
            let mut encrypter = self.session.crypto().encrypter().borrow_mut();
            let algos = self.session.algorithms();

            // Compute mac for unencrypted packet
            let mac = self.session.crypto().compute_mac(
                self.session.integrity_key_server_client(),
                self.session.sequence_number(),
                &packet,
            )?;
            trace!("mac = {:02x?}", mac);

            let mac_length = algos.mac_algorithms_server_to_client.details.hash.size();
            // Allocate vector for encrypted packet with extra space for mac
            let mut packet_enc =
                vec![0u8; PACKET_LENGTH_SIZE + packet_length as usize + mac_length];

            // Encrypt packet
            encrypter.update(&packet, &mut packet_enc)?;

            // Overwrite empty space with mac
            packet_enc[packet.len()..].copy_from_slice(&mac);

            packet = packet_enc;
        }

        debug!(
            "Built packet of type = {:?}",
            MessageType::from_u8(self.payload[0]).unwrap()
        );

        trace!(
            "-- END PACKET ENCODING{} --",
            if self.session.kex().finished {
                " (ENCRYPTED)"
            } else {
                ""
            }
        );
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
    pub fn write_name_list(mut self, names: &[&str]) -> Self {
        self.payload.extend(encode_name_list(names));
        self
    }

    // RFC 4251 § 5
    pub fn write_string(mut self, data: &[u8]) -> Self {
        self.payload.extend(encode_string(data));
        self
    }

    // RFC 4251 § 5
    pub fn write_mpint(mut self, data: &BigNumRef) -> Self {
        self.payload.extend(encode_mpint(data));
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

pub fn encode_name_list(names: &[&str]) -> Vec<u8> {
    trace!("-- BEGIN NAME-LIST ENCODING --");

    let joined = names.join(",");
    trace!("joined = {:?}", joined);

    let payload = joined.as_bytes();

    let mut name_list = Vec::<u8>::new();
    name_list.extend_from_slice(&encode_u32(payload.len() as u32));
    name_list.extend_from_slice(payload);
    trace!("name_list = {:02x?}", name_list);

    trace!("-- END NAME-LIST ENCODING --");
    name_list
}

pub fn encode_string(data: &[u8]) -> Vec<u8> {
    let mut string = Vec::with_capacity(STRING_LENGTH_SIZE + data.len());
    let length_bytes = encode_u32(data.len() as u32);
    string.extend_from_slice(&length_bytes);
    string.extend_from_slice(data);
    string
}

pub fn encode_mpint(data: &BigNumRef) -> Vec<u8> {
    let mut bin = data.to_vec();
    if !bin.is_empty() && (bin[0] & 0b1000_0000) != 0 {
        trace!("Adding a zero byte to the beginning of mpint");
        bin.insert(0, 0);
    }
    encode_string(&bin)
}

// RFC 5656 § 3.1
pub fn encode_ec_public_key(
    algorithm: &Algorithm<HostKeyAlgorithmDetails>,
    key: &[u8],
) -> Result<Vec<u8>> {
    let split: Vec<&str> = algorithm.name.split('-').collect();
    let ident = split.last().unwrap();

    let blob = [encode_string(ident.as_bytes()), encode_string(key)].concat();

    Ok([encode_string(algorithm.name.as_bytes()), blob].concat())
}

// RFC 5656 § 3.1.1
pub fn encode_ec_signature(
    algorithm: &Algorithm<HostKeyAlgorithmDetails>,
    sig: &EcdsaSigRef,
) -> Result<Vec<u8>> {
    let signature_blob = [encode_mpint(sig.r()), encode_mpint(sig.s())].concat();

    Ok([
        encode_string(algorithm.name.as_bytes()),
        encode_string(&signature_blob),
    ]
    .concat())
}
