use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

use algorithm_negotiation::Algorithms;
use anyhow::{anyhow, Context, Result};
use log::{debug, error, trace};
use openssl::symm::{Crypter, Mode};

use crate::{
    crypto::Crypto,
    decoding::{decode_packet, PayloadReader},
    encoding::{encode_mpint, PacketBuilder},
    types::{DisconnectReason, MessageType, ServiceName},
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
    encrypter: Option<RefCell<Crypter>>,
    decrypter: Option<RefCell<Crypter>>,
}

#[derive(Default)]
pub struct KeyExchange {
    pub client_ident: String,
    pub client_kexinit_payload: Vec<u8>,
    pub server_kexinit_payload: Vec<u8>,
    pub finished: bool,
    pub ext_info_c: bool,
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
            encrypter: None,
            decrypter: None,
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
                self.disconnect(reason)?;
                break;
            }
        }

        Ok(())
    }

    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    pub fn algorithms(&self) -> Option<&Algorithms> {
        self.algorithms.as_ref()
    }

    pub fn crypto(&self) -> Option<&Crypto> {
        self.crypto.as_ref()
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

    pub fn decrypter(&self) -> Option<&RefCell<Crypter>> {
        self.decrypter.as_ref()
    }

    pub fn encrypter(&self) -> Option<&RefCell<Crypter>> {
        self.encrypter.as_ref()
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
        let packet = decode_packet(self)?;
        let msg_type = packet.message_type()?;
        debug!(
            "Received message of type = {:?}, sequence_number = {}",
            msg_type, self.sequence_number
        );

        let mut reader = PayloadReader::new(packet.payload());

        match msg_type {
            MessageType::SSH_MSG_DISCONNECT => {
                return Ok(Some(DisconnectReason::SSH_DISCONNECT_BY_APPLICATION))
            }
            MessageType::SSH_MSG_IGNORE => { /* RFC 4253 § 11.2 - Must be ignored */ }
            MessageType::SSH_MSG_UNIMPLEMENTED => { /* RFC 4253 § 11.4 - Must be ignored */ }
            MessageType::SSH_MSG_DEBUG => { /* RFC 4253 § 11.3 - May be ignored */ }
            MessageType::SSH_MSG_SERVICE_REQUEST => {
                debug!("--- BEGIN SERVICE REQUEST ---");

                let service_name = String::from_utf8(reader.next_string()?)?;
                debug!("service_name = {}", service_name);

                if service_name == ServiceName::SSH_USERAUTH {
                    let packet = PacketBuilder::new(MessageType::SSH_MSG_SERVICE_ACCEPT, self)
                        .write_string(service_name.as_bytes())
                        .build()?;
                    self.send_packet(&packet)?;
                } else {
                    return Ok(Some(DisconnectReason::SSH_DISCONNECT_SERVICE_NOT_AVAILABLE));
                }

                debug!("--- END SERVICE REQUEST ---");
            }
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

                // RFC 8308 § 2.3, 2.4
                // Advertise extensions
                // if self.kex().ext_info_c {
                //     let packet = PacketBuilder::new(MessageType::SSH_MSG_EXT_INFO, self)
                //         .write_u32(1)
                //         .write_string(b"server-sig-algs")
                //         .write_name_list(HostKeyAlgorithm::VARIANTS)
                //         .build()?;
                //     self.send_packet(&packet)?;
                // }
            }

            MessageType::SSH_MSG_KEX_ECDH_INIT => {
                let algos = self.algorithms().unwrap().clone();
                let hash_algo = algos.kex_algorithm.details.hash;
                let iv_len = algos
                    .encryption_algorithms_client_to_server
                    .details
                    .cipher
                    .iv_len()
                    .unwrap();
                let block_size = algos
                    .encryption_algorithms_client_to_server
                    .details
                    .block_size;

                let (k, h) = self.key_exchange(&mut reader)?;
                let k = encode_mpint(&k);
                let k = k.as_slice();
                let h = h.as_slice();

                self.session_id = h.to_vec();
                self.iv_client_server =
                    Crypto::hash(&[k, h, b"A", h].concat(), hash_algo)?[..iv_len].to_vec();
                self.iv_server_client =
                    Crypto::hash(&[k, h, b"B", h].concat(), hash_algo)?[..iv_len].to_vec();
                self.enc_key_client_server =
                    Crypto::hash(&[k, h, b"C", h].concat(), hash_algo)?[..block_size].to_vec();
                self.enc_key_server_client =
                    Crypto::hash(&[k, h, b"D", h].concat(), hash_algo)?[..block_size].to_vec();
                self.integrity_key_client_server =
                    Crypto::hash(&[k, h, b"E", h].concat(), hash_algo)?;
                self.integrity_key_server_client =
                    Crypto::hash(&[k, h, b"F", h].concat(), hash_algo)?;

                let mut encrypter = Crypter::new(
                    algos.encryption_algorithms_server_to_client.details.cipher,
                    Mode::Encrypt,
                    self.enc_key_server_client(),
                    Some(self.iv_server_client()),
                )?;
                encrypter.pad(false);
                self.encrypter = Some(RefCell::new(encrypter));

                let mut decrypter = Crypter::new(
                    algos.encryption_algorithms_client_to_server.details.cipher,
                    Mode::Decrypt,
                    self.enc_key_client_server(),
                    Some(self.iv_client_server()),
                )?;
                decrypter.pad(false);
                self.decrypter = Some(RefCell::new(decrypter));

                if cfg!(debug_assertions) {
                    trace!("session_id = {:02x?}", self.session_id);
                    trace!("iv_len = {}", iv_len);
                    trace!("iv_client_server = {:02x?}", self.iv_client_server);
                    trace!("iv_server_client = {:02x?}", self.iv_server_client);
                    trace!("block_size = {}", block_size);
                    trace!(
                        "enc_key_client_server = {:02x?}",
                        self.enc_key_client_server
                    );
                    trace!(
                        "enc_key_server_client = {:02x?}",
                        self.enc_key_server_client
                    );
                    trace!(
                        "integrity_key_client_server = {:02x?}",
                        self.integrity_key_client_server
                    );
                    trace!(
                        "integrity_key_server_client = {:02x?}",
                        self.integrity_key_server_client
                    );
                }
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
        trace!("Packet sent");

        Ok(())
    }

    // RFC 4253 § 11.1
    fn disconnect(&mut self, reason: DisconnectReason) -> Result<()> {
        let packet = PacketBuilder::new(MessageType::SSH_MSG_DISCONNECT, self)
            .write_byte(reason as u8)
            .write_bytes(b"")
            .write_bytes(b"en")
            .build()?;
        self.send_packet(&packet)?;

        debug!("Disconnecting because of {:?}", &reason);
        Ok(())
    }
}
