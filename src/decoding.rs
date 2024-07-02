use std::{
    io::{BufReader, Read},
    mem::size_of,
    net::TcpStream,
};

use anyhow::{bail, Context, Result};
use log::trace;
use num_traits::FromPrimitive;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::Public,
};

use crate::{
    encoding::{encode_string, PACKET_LENGTH_SIZE, STRING_LENGTH_SIZE},
    hex_dump,
    session::Session,
    types::MessageType,
};

const MAX_PACKET_LENGTH: u32 = 65535;

pub struct PayloadReader {
    iter: std::vec::IntoIter<u8>,
}

#[allow(dead_code)]
impl PayloadReader {
    pub fn new(payload: Vec<u8>) -> Self {
        PayloadReader {
            iter: payload.into_iter(),
        }
    }

    // RFC 4251 § 5
    pub fn next_name_list(&mut self) -> Result<Vec<String>> {
        let iter = &mut self.iter;
        let length_bytes: Vec<u8> = iter.take(PACKET_LENGTH_SIZE).collect();

        let length = u8_array_to_u32(length_bytes.as_slice())?;

        let value_bytes: Vec<u8> = iter.take(length as usize).collect();
        let value =
            String::from_utf8(value_bytes).context("Failed to decode name-list to string")?;

        let name_list = value.split(',').map(String::from).collect();
        Ok(name_list)
    }

    // RFC 4251 § 5
    pub fn next_string(&mut self) -> Result<Vec<u8>> {
        let iter = &mut self.iter;
        let length_bytes: Vec<u8> = iter.take(STRING_LENGTH_SIZE).collect();
        let length = u8_array_to_u32(&length_bytes)?;

        let string = iter.take(length as usize).collect();
        Ok(string)
    }

    pub fn next_string_utf8(&mut self) -> Result<String> {
        let bytes = self.next_string()?;
        String::from_utf8(bytes).context("Failed to decode string bytes to UTF-8")
    }

    pub fn next_byte(&mut self) -> Result<u8> {
        let byte = self
            .iter
            .next()
            .context("Failed to read next byte, packet too short")?;

        Ok(byte)
    }

    pub fn next_n_bytes(&mut self, n: usize) -> Vec<u8> {
        let bytes = self.iter.by_ref().take(n).collect();
        bytes
    }

    pub fn next_u32(&mut self) -> Result<u32> {
        let bytes = self.next_n_bytes(4);
        u8_array_to_u32(&bytes)
    }

    pub fn next_bool(&mut self) -> Result<bool> {
        let byte = self.next_byte()?;
        let bool = u8_to_bool(byte)?;
        Ok(bool)
    }

    pub fn next_mpint(&mut self) -> Result<BigNum> {
        let mut bytes = self.next_string()?;
        if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
            bail!("Negative numbers are not supported");
        }

        if !bytes.is_empty() && bytes[0] == 0 {
            bytes.remove(0);
        }

        Ok(BigNum::from_slice(&bytes)?)
    }

    pub fn rest(&mut self) -> Vec<u8> {
        self.iter.by_ref().collect()
    }
}

#[derive(Debug)]
pub struct DecodedPacket {
    payload: Vec<u8>,
}

impl DecodedPacket {
    pub fn message_type(&self) -> Result<MessageType> {
        if self.payload.is_empty() {
            bail!("Payload is empty");
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
}

// RFC 4253 § 6
pub fn decode_packet(
    session: &mut Session,
    reader: &mut BufReader<TcpStream>,
) -> Result<DecodedPacket> {
    trace!(
        "-- BEGIN PACKET DECODING{} --",
        if session.kex().finished {
            " (ENCRYPTED)"
        } else {
            ""
        }
    );

    let decoded_packet = if session.kex().finished {
        decode_packet_encrypted(session, reader)?
    } else {
        decode_packet_unencrypted(reader)?
    };

    trace!(
        "-- END PACKET DECODING{} --",
        if session.kex().finished {
            " (ENCRYPTED)"
        } else {
            ""
        }
    );
    Ok(decoded_packet)
}
fn decode_packet_encrypted(
    session: &Session,
    reader: &mut BufReader<TcpStream>,
) -> Result<DecodedPacket> {
    let block_size = session
        .algorithms()
        .encryption_algorithms_client_to_server
        .details
        .block_size;

    let crypto = session.crypto().read().unwrap();
    let mut decrypter = crypto.decrypter().write().unwrap();

    // Read first block
    let mut first_block = vec![0u8; block_size];
    reader.read_exact(&mut first_block)?;

    // Decrypt first block to get packet length
    let mut first_block_dec = vec![0u8; block_size];
    decrypter.update(&first_block, &mut first_block_dec)?;

    let packet_length_bytes = &first_block_dec[0..PACKET_LENGTH_SIZE];
    let packet_length = u8_array_to_u32(packet_length_bytes)?;
    if packet_length > MAX_PACKET_LENGTH {
        bail!(
            "Packet length {} exceeds maximum length {}",
            packet_length,
            MAX_PACKET_LENGTH
        );
    }
    trace!("packet_length = {}", packet_length);

    // Read rest of encrypted packet
    let mut rest_enc = vec![0u8; packet_length as usize - (block_size - PACKET_LENGTH_SIZE)];
    reader.read_exact(&mut rest_enc)?;

    // Decrypt rest of encrypted packet
    let mut rest_dec = vec![0u8; rest_enc.len()];
    decrypter.update(&rest_enc, &mut rest_dec)?;

    // Join first block and rest of decrypted packet
    let mut packet_dec = first_block_dec[PACKET_LENGTH_SIZE..].to_vec();
    packet_dec.extend(rest_dec);

    let mac_len = session
        .algorithms()
        .mac_algorithms_client_to_server
        .details
        .hash
        .size();
    let mut mac = vec![0u8; mac_len];
    reader.read_exact(&mut mac)?;

    let valid = crypto.verify_mac(
        session.client_sequence_number(),
        &session.secrets().integrity_key_client_server,
        // For some reason, this has to be encoded as string
        &encode_string(&packet_dec),
        &mac,
    )?;
    if !valid {
        bail!("MAC verification failed");
    }

    let payload = get_payload(packet_dec, packet_length)?;
    Ok(DecodedPacket { payload })
}
fn decode_packet_unencrypted(reader: &mut BufReader<TcpStream>) -> Result<DecodedPacket> {
    let mut packet_length_bytes = [0u8; PACKET_LENGTH_SIZE];
    reader
        .read_exact(&mut packet_length_bytes)
        .context("Failed reading packet_length")?;
    let packet_length = u8_array_to_u32(&packet_length_bytes)?;
    if packet_length > MAX_PACKET_LENGTH {
        bail!(
            "Packet length {} exceeds maximum length {}",
            packet_length,
            MAX_PACKET_LENGTH
        );
    }
    trace!("packet_length = {} bytes", packet_length);

    let mut packet = vec![0u8; packet_length as usize];
    reader
        .read_exact(&mut packet)
        .context("Failed reading packet")?;

    let payload = get_payload(packet, packet_length)?;
    Ok(DecodedPacket { payload })
}
/// `packet` must not contain the packet_length field
fn get_payload(packet: Vec<u8>, packet_length: u32) -> Result<Vec<u8>> {
    let reader = &mut packet.into_iter();

    let padding_length = reader.next().context("Could not read padding_length")?;
    trace!("padding_length = {} bytes", padding_length);

    let n1 = packet_length - (padding_length as u32) - 1;
    let payload: Vec<u8> = reader.take(n1 as usize).collect();
    hex_dump!(payload);

    let random_padding = reader.take(padding_length as usize).collect::<Vec<u8>>();
    trace!("random_padding = {:02x?}", random_padding);

    let bytes_left = packet_length - size_of::<u8>() as u32 - n1 - padding_length as u32;
    if bytes_left != 0 {
        bail!("Didn't decode entire packet, {} bytes left", bytes_left);
    }

    Ok(payload)
}

// RFC 5656 § 3.1
/// `(public_key_bytes, ec_key)`
pub fn decode_ec_public_key(key: &[u8], curve: Nid) -> Result<(Vec<u8>, EcKey<Public>)> {
    trace!("--- BEGIN EC PUBLIC KEY DECODING ---");
    let mut reader = PayloadReader::new(key.to_vec());

    let name = reader.next_string_utf8()?;
    trace!("name = {:?}", name);

    let ident = reader.next_string_utf8()?;
    trace!("ident = {:?}", ident);

    let q = reader.next_string()?;
    trace!("q = {:02x?}", q);

    let mut ctx = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(curve)?;
    let ec_point = EcPoint::from_bytes(&group, &q, &mut ctx)?;
    let ec_key = EcKey::from_public_key(&group, &ec_point)?;

    trace!("--- END EC PUBLIC KEY DECODING ---");
    Ok((q, ec_key))
}

// RFC 5656 § 3.1.1
pub fn decode_ec_signature(sig: &[u8]) -> Result<EcdsaSig> {
    trace!("--- BEGIN EC SIGNATURE DECODING ---");

    let mut reader = PayloadReader::new(sig.to_vec());
    let _name = reader.next_string()?;
    let blob = reader.next_string()?;

    let mut blob_reader = PayloadReader::new(blob);
    let r = blob_reader.next_mpint()?;
    trace!("r = {:?}", r);

    let s = blob_reader.next_mpint()?;
    trace!("s = {:?}", s);

    trace!("--- BEGIN EC SIGNATURE DECODING ---");
    Ok(EcdsaSig::from_private_components(r, s)?)
}

pub fn u8_array_to_u32(array: &[u8]) -> Result<u32> {
    if array.len() != 4 {
        bail!("Cannot convert u8 array of length {} to u32", array.len());
    }

    Ok(u32::from_be_bytes([array[0], array[1], array[2], array[3]]))
}

pub fn u8_to_bool(value: u8) -> Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => bail!("Cannot convert u8 of value {} to bool", value),
    }
}

#[allow(non_snake_case)]
pub fn u8_to_MessageType(value: u8) -> Result<MessageType> {
    MessageType::from_u8(value).context(format!("Failed to cast {} into MessageType", value))
}
