use std::{
    io::{BufReader, Read},
    net::TcpStream,
};

use anyhow::{anyhow, Context, Result};
use log::{log_enabled, trace, Level};
use num_traits::FromPrimitive;
use openssl::{
    base64,
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{Private, Public},
};

use crate::{
    encoding::{encode_string, PACKET_LENGTH_SIZE, STRING_LENGTH_SIZE},
    session::{algorithm_negotiation::Algorithm, Session},
    types::{HostKeyAlgorithmDetails, MessageType},
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
        let iter = self.iter.by_ref();
        let length_bytes = iter.take(PACKET_LENGTH_SIZE).collect::<Vec<u8>>();

        let length = u8_array_to_u32(length_bytes.as_slice())?;

        let value_bytes = iter.take(length as usize).collect::<Vec<u8>>();
        let value =
            String::from_utf8(value_bytes).context("Failed to decode name-list to string")?;

        let name_list = value.split(',').map(String::from).collect();
        Ok(name_list)
    }

    // RFC 4251 § 5
    pub fn next_string(&mut self) -> Result<Vec<u8>> {
        let iter = self.iter.by_ref();
        let length_bytes = iter.take(STRING_LENGTH_SIZE).collect::<Vec<u8>>();
        let length = u8_array_to_u32(&length_bytes)?;

        let string = iter.take(length as usize).collect();
        Ok(string)
    }

    pub fn next_byte(&mut self) -> Option<u8> {
        let byte = self.iter.by_ref().next()?;
        Some(byte)
    }

    pub fn next_n_bytes(&mut self, n: usize) -> Vec<u8> {
        let bytes = self.iter.by_ref().take(n).collect();
        bytes
    }

    pub fn next_u32(&mut self) -> Result<u32> {
        let bytes = self.next_n_bytes(4);
        u8_array_to_u32(&bytes)
    }

    pub fn next_bool(&mut self) -> Option<bool> {
        let byte = self.next_byte()?;
        if byte == 0 {
            Some(false)
        } else {
            Some(true)
        }
    }

    pub fn next_mpint(&mut self) -> Result<BigNum> {
        let mut bytes = self.next_string()?;
        if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
            return Err(anyhow!("Negative numbers are not supported"));
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
}

// RFC 4253 § 6
pub fn decode_packet(session: &mut Session) -> Result<DecodedPacket> {
    trace!(
        "-- BEGIN PACKET DECODING{} --",
        if session.kex().finished {
            " (ENCRYPTED)"
        } else {
            ""
        }
    );

    let decoded_packet = if session.kex().finished {
        decode_packet_encrypted(session)?
    } else {
        decode_packet_unencrypted(session.stream())?
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
fn decode_packet_encrypted(session: &Session) -> Result<DecodedPacket> {
    let block_size = session
        .algorithms()
        .encryption_algorithms_client_to_server
        .details
        .block_size;

    let mut decrypter = session.crypto().decrypter().borrow_mut();

    // Read first block
    let mut reader = BufReader::new(session.stream());
    let mut first_block = vec![0u8; block_size];
    reader.read_exact(&mut first_block)?;

    // Decrypt first block to get packet length
    let mut first_block_dec = vec![0u8; block_size];
    decrypter.update(&first_block, &mut first_block_dec)?;

    let packet_length_bytes = &first_block_dec[0..PACKET_LENGTH_SIZE];
    let packet_length = u8_array_to_u32(packet_length_bytes)?;
    if packet_length > MAX_PACKET_LENGTH {
        return Err(anyhow!(
            "Packet length {} exceeds maximum length {}",
            packet_length,
            MAX_PACKET_LENGTH
        ));
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

    let valid = session.crypto().verify_mac(
        session.client_sequence_number(),
        session.integrity_key_client_server(),
        // For some reason, this has to be encoded as string
        &encode_string(&packet_dec),
        &mac,
    )?;
    if !valid {
        return Err(anyhow!("MAC verification failed"));
    }

    trace!("packet = {:02x?}", packet_dec);

    let payload = get_payload(packet_dec, packet_length)?;
    Ok(DecodedPacket { payload })
}
fn decode_packet_unencrypted(stream: &TcpStream) -> Result<DecodedPacket> {
    let mut reader = BufReader::new(stream);

    let mut packet_length_bytes = [0u8; PACKET_LENGTH_SIZE];
    reader
        .read_exact(&mut packet_length_bytes)
        .context("Failed reading packet_length")?;
    let packet_length = u8_array_to_u32(&packet_length_bytes)?;
    if packet_length > MAX_PACKET_LENGTH {
        return Err(anyhow!(
            "Packet length {} exceeds maximum length {}",
            packet_length,
            MAX_PACKET_LENGTH
        ));
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
    let mut reader = packet.into_iter();
    let reader = reader.by_ref();

    let padding_length = *reader.take(1).collect::<Vec<u8>>().first().unwrap();
    trace!("padding_length = {} bytes", padding_length);

    let n1 = packet_length - (padding_length as u32) - 1;
    let payload = reader.take(n1 as usize).collect::<Vec<u8>>();

    if log_enabled!(Level::Trace) {
        trace!("payload = {:?}", String::from_utf8_lossy(&payload));
    }

    let random_padding = reader.take(padding_length as usize).collect::<Vec<u8>>();
    trace!("random_padding = {:02x?}", random_padding);

    let bytes_left = packet_length - 1 - n1 - padding_length as u32;
    if bytes_left != 0 {
        return Err(anyhow!(
            "Didn't decode entire packet, {} bytes left",
            bytes_left
        ));
    }

    Ok(payload)
}

// https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.key
pub fn decode_openssh_ec_private_key(
    pem: &str,
    algo: &Algorithm<HostKeyAlgorithmDetails>,
) -> Result<EcKey<Private>> {
    trace!("--- BEGIN PRIVATE KEY DECODING ---");

    const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

    let private_key = pem
        .split('\n')
        .filter(|s| !s.is_empty())
        .collect::<Vec<&str>>();
    let private_key_contents = &private_key[1..private_key.len() - 1].join("");
    let private_key_blob = base64::decode_block(private_key_contents)?;
    trace!("private_key_blob = {:02x?}", private_key_blob);

    let mut reader = PayloadReader::new(private_key_blob);

    let auth_magic = reader.next_n_bytes(AUTH_MAGIC.len());
    if auth_magic != AUTH_MAGIC {
        return Err(anyhow!(
            "Invalid private key format '{}'",
            String::from_utf8_lossy(&auth_magic)
        ));
    }
    trace!("auth_magic = {:?}", String::from_utf8(auth_magic)?);

    let cipher_name = String::from_utf8(reader.next_string()?)?;
    trace!("cipher_name = {:?}", cipher_name);
    if cipher_name != "none" {
        return Err(anyhow!("Keys encrypted using passphrase are not supported"));
    }

    let kdf_name = String::from_utf8(reader.next_string()?)?;
    trace!("kdf_name = {:?}", kdf_name);

    let kdf_options = String::from_utf8(reader.next_string()?)?;
    trace!("kdf_options = {:?}", kdf_options);

    let _num_keys = reader.next_u32()?;

    let (public_key_bytes, public_key) = decode_ec_public_key(&reader.next_string()?, &algo)?;
    trace!("public_key = {:02x?}", public_key_bytes);

    let private_keys_list = reader.next_string()?;
    trace!("private_keys_list = {:02x?}", private_keys_list);

    let mut private_key_reader = PayloadReader::new(private_keys_list);
    let checkint1 = private_key_reader.next_u32()?;
    trace!("checkint1 = {}", checkint1);

    let checkint2 = private_key_reader.next_u32()?;
    trace!("checkint2 = {}", checkint2);

    if checkint1 != checkint2 {
        return Err(anyhow!("checkint1 != checkint2"));
    }

    let _private_key_public_key_part =
        decode_ec_key_public_key_reader(&mut private_key_reader, algo)?;
    let private_key = BigNum::from_slice(&private_key_reader.next_string()?)?;
    trace!("private_key = {:02x?}", private_key);

    let comment = String::from_utf8(private_key_reader.next_string()?)?;
    trace!("comment = {}", comment);

    let ec_group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::from_private_components(&ec_group, &private_key, public_key.public_key())?;

    trace!("--- END PRIVATE KEY DECODING ---");
    Ok(ec_key)
}

// RFC 5656 § 3.1
/// `(public_key_bytes,_ec_key)`
pub fn decode_ec_public_key(
    key: &[u8],
    algo: &Algorithm<HostKeyAlgorithmDetails>,
) -> Result<(Vec<u8>, EcKey<Public>)> {
    let mut reader = PayloadReader::new(key.to_vec());
    let (q, ec_key) = decode_ec_key_public_key_reader(&mut reader, algo)?;

    Ok((q, ec_key))
}
fn decode_ec_key_public_key_reader(
    reader: &mut PayloadReader,
    algo: &Algorithm<HostKeyAlgorithmDetails>,
) -> Result<(Vec<u8>, EcKey<Public>)> {
    trace!("--- BEGIN EC PUBLIC KEY DECODING ---");

    let name = String::from_utf8(reader.next_string()?)?;
    trace!("name = {:?}", name);

    let ident = String::from_utf8(reader.next_string()?)?;
    trace!("ident = {:?}", ident);

    let q = reader.next_string()?;
    trace!("q = {:02x?}", q);

    let mut ctx = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(algo.details.curve)?;
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
