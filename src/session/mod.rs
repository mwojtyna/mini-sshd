use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

use algorithm_negotiation::Algorithms;
use anyhow::{anyhow, Context, Result};
use log::{debug, error, trace};

use crate::{
    decoding::{decode_packet, u8_to_MessageType},
    encoding::{encode_packet, u32_to_u8_array},
    types::{DisconnectReason, MessageType},
    ServerConfig,
};

pub mod algorithm_negotiation;
pub mod key_exchange;

pub struct Session {
    stream: TcpStream,
    outgoing_packet_sequence: u32,
    incoming_packet_sequence: u32,

    algorithms: Algorithms,
    server_config: ServerConfig,

    // For ECDH kex exchange
    client_ident: String,
    client_kexinit_payload: Vec<u8>,
    server_kexinit_payload: Vec<u8>,
}

impl Session {
    pub fn new(stream: TcpStream, server_config: ServerConfig) -> Self {
        Session {
            stream,
            outgoing_packet_sequence: 0,
            incoming_packet_sequence: 0,

            algorithms: Algorithms::default(),
            server_config,

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

        // First request after ident exchange is always key exchange
        let mut packet = decode_packet(&self.stream)?;
        if u8_to_MessageType(packet.payload.remove(0))? != MessageType::SSH_MSG_KEXINIT {
            self.disconnect(DisconnectReason::SSH_DISCONNECT_PROTOCOL_ERROR)?;
            return Err(anyhow!("Expected key exchange packet"));
        }

        self.algorithms = self
            .algorithm_negotiation(packet)
            .context("Failed during key exchange")?;

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

    // RFC 4253 § 4.2
    fn ident_exchange(&mut self) -> Result<String> {
        debug!("--- BEGIN IDENTIFICATION EXCHANGE ---");
        self.send_packet(format!("{}\r\n", self.server_config.ident_string).as_bytes())?;

        let mut reader = BufReader::new(&mut self.stream);
        let mut client_ident = String::new();
        self.incoming_packet_sequence += reader
            .read_line(&mut client_ident)
            .context("Failed reading client_ident")?
            as u32;
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

    fn handle_packet(&mut self) -> Result<Option<DisconnectReason>> {
        let mut decoded_packet = decode_packet(&self.stream)?;
        self.incoming_packet_sequence += decoded_packet.entire_packet_length;

        let msg_type = u8_to_MessageType(decoded_packet.payload.remove(0))?;
        trace!(
            "Received message of type = {:?}, current packet sequence = {}",
            msg_type,
            self.incoming_packet_sequence
        );

        match msg_type {
            MessageType::SSH_MSG_DISCONNECT => {
                return Ok(Some(DisconnectReason::SSH_DISCONNECT_BY_APPLICATION))
            }
            MessageType::SSH_MSG_IGNORE => { /* RFC 4253 § 11.2 - Must be ignored */ }
            MessageType::SSH_MSG_UNIMPLEMENTED => { /* RFC 4253 § 11.4 - Must be ignored */ }
            MessageType::SSH_MSG_DEBUG => { /* RFC 4253 § 11.3 - May be ignored */ }

            MessageType::SSH_MSG_KEXINIT => {
                decoded_packet
                    .payload
                    .clone_into(&mut self.client_kexinit_payload);
                self.algorithm_negotiation(decoded_packet)
                    .context("Failed during handling SSH_MSG_KEXINIT")?;
            }

            MessageType::SSH_MSG_KEX_ECDH_INIT => {
                self.key_exchange(decoded_packet)
                    .context("Failed during handling SSH_MSG_KEX_ECDH_INIT")?;
            }

            _ => {
                error!(
                    "Unhandled message type.\ntype: {:?}\npayload: {:?}",
                    msg_type,
                    String::from_utf8_lossy(&decoded_packet.payload)
                );

                let payload = [
                    vec![MessageType::SSH_MSG_UNIMPLEMENTED as u8],
                    u32_to_u8_array(self.incoming_packet_sequence).to_vec(),
                ]
                .concat();
                let packet = encode_packet(&payload)?;
                self.send_packet(&packet)?;
            }
        }

        Ok(None)
    }

    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.outgoing_packet_sequence += packet.len() as u32;
        self.stream
            .write_all(packet)
            .context("Failed sending packet")?;

        Ok(())
    }

    // RFC 4253 § 11.1
    fn disconnect(&mut self, reason: DisconnectReason) -> Result<()> {
        let payload = &[
            vec![MessageType::SSH_MSG_DISCONNECT as u8],
            vec![reason.clone() as u8],
            b"".to_vec(),
            b"en".to_vec(),
        ]
        .concat();

        let packet = encode_packet(payload)?;
        self.send_packet(&packet)?;

        debug!("Disconnecting because of {:?}", &reason);

        Ok(())
    }
}
