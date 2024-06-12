use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

use algorithm_negotiation::Algorithms;
use anyhow::{anyhow, Context, Result};
use log::{debug, error, trace};

use crate::{
    crypto::Crypto,
    decoding::{decode_packet, PayloadReader},
    encoding::{encode_mpint, PacketBuilder},
    types::{DisconnectReason, MessageType},
    ServerConfig,
};

pub mod algorithm_negotiation;
pub mod key_exchange;

pub struct Session<'a> {
    stream: TcpStream,
    sequence_number: u32,

    server_config: &'a ServerConfig,
    algorithms: Option<Algorithms>,
    crypto: Option<Crypto>,

    kex: KeyExchange,

    // Secrets
    session_id: Vec<u8>,
    iv_client_server: Vec<u8>,
    iv_server_client: Vec<u8>,
    enc_key_client_server: Vec<u8>,
    enc_key_server_client: Vec<u8>,
    integrity_key_client_server: Vec<u8>,
    integrity_key_server_client: Vec<u8>,
}

#[derive(Default)]
pub struct KeyExchange {
    pub client_ident: String,
    pub client_kexinit_payload: Vec<u8>,
    pub server_kexinit_payload: Vec<u8>,
    pub finished: bool,
}

impl<'a> Session<'a> {
    pub fn new(stream: TcpStream, server_config: &'a ServerConfig) -> Self {
        Session {
            stream,
            sequence_number: 0,

            server_config,
            algorithms: None,
            crypto: None,

            kex: KeyExchange::default(),

            session_id: Vec::new(),
            iv_client_server: Vec::new(),
            iv_server_client: Vec::new(),
            enc_key_client_server: Vec::new(),
            enc_key_server_client: Vec::new(),
            integrity_key_client_server: Vec::new(),
            integrity_key_server_client: Vec::new(),
        }
    }

    /// This will handle all incoming packets, blocking this thread until disconnect.
    pub fn start(&mut self) -> Result<()> {
        debug!(
            "Spawned new thread for client on address {}",
            self.stream.peer_addr().unwrap()
        );

        self.kex.client_ident = self
            .ident_exchange()
            .context("Failed during ident exchange")?;

        loop {
            let disconnect = self.handle_packet().context("Failed handling packet")?;
            if let Some(reason) = disconnect {
                debug!("Sending disconnect packet, reason = {:?}", reason);
                self.disconnect(reason)?;
                break;
            }
        }

        Ok(())
    }

    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    pub fn algorithms(&self) -> &Option<Algorithms> {
        &self.algorithms
    }

    pub fn kex(&self) -> &KeyExchange {
        &self.kex
    }

    pub fn iv_client_server(&self) -> &Vec<u8> {
        &self.iv_client_server
    }

    pub fn iv_server_client(&self) -> &Vec<u8> {
        &self.iv_server_client
    }

    pub fn enc_key_client_server(&self) -> &Vec<u8> {
        &self.enc_key_client_server
    }

    pub fn enc_key_server_client(&self) -> &Vec<u8> {
        &self.enc_key_server_client
    }

    pub fn integrity_key_server_client(&self) -> &Vec<u8> {
        &self.integrity_key_server_client
    }

    pub fn integrity_key_client_server(&self) -> &Vec<u8> {
        &self.integrity_key_client_server
    }

    // RFC 4253 § 4.2
    fn ident_exchange(&mut self) -> Result<String> {
        debug!("--- BEGIN IDENTIFICATION EXCHANGE ---");
        self.send_packet(format!("{}\r\n", self.server_config.ident_string).as_bytes())?;

        let mut reader = BufReader::new(&mut self.stream);
        let mut client_ident = String::new();
        reader
            .read_line(&mut client_ident)
            .context("Failed reading client_ident")?;

        client_ident = client_ident.lines().next().unwrap().to_string();
        debug!("client = {:?}", client_ident);

        if let Some(proto_version_str) = client_ident.split('-').nth(1) {
            if let Ok(proto_version) = proto_version_str.parse::<f32>() {
                trace!("proto_version = {:?}", proto_version);
                if !(2.0..3.0).contains(&proto_version) {
                    self.disconnect(
                        DisconnectReason::SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                    )?;
                    return Err(anyhow!(
                        "Unsupported protocol version of {:?}",
                        proto_version
                    ));
                }
            } else {
                self.disconnect(DisconnectReason::SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED)?;
                return Err(anyhow!(
                    "Could not parse protocol version '{:?}'",
                    proto_version_str
                ));
            }
        } else {
            self.disconnect(DisconnectReason::SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED)?;
            return Err(anyhow!(
                "Could not find protocol version in client ident string of '{:?}'",
                client_ident
            ));
        }

        debug!("--- END IDENTIFICATION EXCHANGE ---");
        Ok(client_ident)
    }

    // TODO: Handle packets like `ssh_dispatch_set` from openssh
    fn handle_packet(&mut self) -> Result<Option<DisconnectReason>> {
        let packet = decode_packet(&self.stream, self)?;
        let msg_type = packet.message_type()?;
        trace!(
            "Received message of type = {:?}, sequence_number = {}",
            msg_type,
            self.sequence_number
        );

        let mut reader = PayloadReader::new(packet.payload());

        match msg_type {
            MessageType::SSH_MSG_DISCONNECT => {
                return Ok(Some(DisconnectReason::SSH_DISCONNECT_BY_APPLICATION))
            }
            MessageType::SSH_MSG_IGNORE => { /* RFC 4253 § 11.2 - Must be ignored */ }
            MessageType::SSH_MSG_UNIMPLEMENTED => { /* RFC 4253 § 11.4 - Must be ignored */ }
            MessageType::SSH_MSG_DEBUG => { /* RFC 4253 § 11.3 - May be ignored */ }

            MessageType::SSH_MSG_KEXINIT => {
                let algorithms = self
                    .algorithm_negotiation(&packet, &mut reader)
                    .context("Failed during handling SSH_MSG_KEXINIT")?;

                self.algorithms = Some(algorithms.clone());
                self.crypto = Some(Crypto::new(algorithms));
            }
            MessageType::SSH_MSG_NEWKEYS => {
                let packet = PacketBuilder::new(MessageType::SSH_MSG_NEWKEYS, self).build()?;
                self.send_packet(&packet)?;
                self.kex.finished = true;
            }

            MessageType::SSH_MSG_KEX_ECDH_INIT => {
                let (k, h) = self.key_exchange(&mut reader)?;
                let hash_algo = self
                    .algorithms()
                    .as_ref()
                    .unwrap()
                    .kex_algorithm
                    .details
                    .hash;

                let k = encode_mpint(&k);
                let k = k.as_slice();
                let h = h.as_slice();

                if cfg!(debug_assertions) {
                    debug!("k = {:02x?}", k);
                    debug!("h = {:02x?}", h);
                }

                self.session_id = h.to_vec();
                self.iv_client_server = Crypto::hash(&[k, h, b"A", h].concat(), hash_algo)?;
                self.iv_server_client = Crypto::hash(&[k, h, b"B", h].concat(), hash_algo)?;
                self.enc_key_client_server =
                    Crypto::hash(&[k, h, b"C", h].concat(), hash_algo)?[0..(128 / 8)].to_vec();
                self.enc_key_server_client =
                    Crypto::hash(&[k, h, b"D", h].concat(), hash_algo)?[0..(128 / 8)].to_vec();
                self.integrity_key_client_server =
                    Crypto::hash(&[k, h, b"E", h].concat(), hash_algo)?;
                self.integrity_key_server_client =
                    Crypto::hash(&[k, h, b"F", h].concat(), hash_algo)?;
            }

            _ => {
                error!(
                    "Unhandled message type.\ntype: {:?}\npayload: {:?}",
                    msg_type,
                    String::from_utf8_lossy(&packet.payload())
                );

                let packet = PacketBuilder::new(MessageType::SSH_MSG_UNIMPLEMENTED, self)
                    .write_u32(self.sequence_number)
                    .build()?;
                self.send_packet(&packet)?;
            }
        }

        self.sequence_number = self.sequence_number.wrapping_add(1);
        Ok(None)
    }

    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.stream
            .write_all(packet)
            .context("Failed sending packet")?;

        Ok(())
    }

    // RFC 4253 § 11.1
    fn disconnect(&mut self, reason: DisconnectReason) -> Result<()> {
        let packet = PacketBuilder::new(MessageType::SSH_MSG_DISCONNECT, self)
            .write_byte(reason.clone() as u8)
            .write_bytes(b"")
            .write_bytes(b"en")
            .build()?;
        self.send_packet(&packet)?;

        debug!("Disconnecting because of {:?}", &reason);
        Ok(())
    }
}
