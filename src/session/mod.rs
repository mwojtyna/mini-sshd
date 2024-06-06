use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

use algorithm_negotiation::Algorithms;
use anyhow::{anyhow, Context, Result};
use log::{debug, error, trace};

use crate::{
    decoding::{decode_packet, PayloadReader},
    encoding::PacketBuilder,
    types::{DisconnectReason, MessageType},
    ServerConfig,
};

pub mod algorithm_negotiation;
pub mod key_exchange;

pub struct Session {
    stream: TcpStream,
    sequence_number: u32,

    server_config: ServerConfig,
    algorithms: Option<Algorithms>,
    shared_secret: Option<Vec<u8>>,

    // For ECDH kex exchange
    client_ident: String,
    client_kexinit_payload: Vec<u8>,
    server_kexinit_payload: Vec<u8>,
}

impl Session {
    pub fn new(stream: TcpStream, server_config: ServerConfig) -> Self {
        Session {
            stream,
            sequence_number: 0,

            server_config,
            algorithms: None,
            shared_secret: None,

            client_ident: String::new(),
            client_kexinit_payload: Vec::new(),
            server_kexinit_payload: Vec::new(),
        }
    }

    /// This will handle all incoming packets, blocking this thread until disconnect.
    pub fn start(&mut self) -> Result<()> {
        debug!(
            "Spawned new thread for client on address {}",
            self.stream.peer_addr().unwrap()
        );

        self.client_ident = self
            .ident_exchange()
            .context("Failed during ident exchange")?;

        loop {
            let disconnect = self.handle_packet().context("Failed handling packet")?;
            if let Some(reason) = disconnect {
                if reason != DisconnectReason::SSH_DISCONNECT_BY_APPLICATION {
                    debug!("Sending disconnect packet, reason = {:?}", reason);
                    self.disconnect(reason)?;
                }
                break;
            }
        }

        Ok(())
    }

    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    pub fn shared_secret(&self) -> &Option<Vec<u8>> {
        &self.shared_secret
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
        let packet = decode_packet(&self.stream)?;
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
                self.algorithms = Some(
                    self.algorithm_negotiation(&packet, &mut reader)
                        .context("Failed during handling SSH_MSG_KEXINIT")?,
                );
            }
            MessageType::SSH_MSG_NEWKEYS => {
                let packet = PacketBuilder::new(MessageType::SSH_MSG_NEWKEYS, self).build()?;
                self.send_packet(&packet)?;
            }

            MessageType::SSH_MSG_KEX_ECDH_INIT => {
                self.shared_secret = Some(
                    self.key_exchange(&mut reader)
                        .context("Failed during handling SSH_MSG_KEX_ECDH_INIT")?,
                );
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
