use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

use anyhow::{anyhow, Context, Result};
use key_exchange::Algorithms;
use log::{debug, error, trace};

use crate::{
    decoding::{decode_packet, u8_to_MessageType},
    encoding::{encode_packet, u32_to_u8_array},
    types::{DisconnectReason, MessageType},
    IDENT_STRING,
};

mod key_exchange;

pub struct Session {
    stream: TcpStream,
    outgoing_packet_sequence: u32,
    incoming_packet_sequence: u32,
    client_algorithms: Algorithms,
}

impl Session {
    pub fn new(stream: TcpStream) -> Self {
        Session {
            outgoing_packet_sequence: 0,
            incoming_packet_sequence: 0,
            stream,
            client_algorithms: Algorithms::default(),
        }
    }

    /// This will handle all incoming packets, blocking this thread until disconnect.
    pub fn start(&mut self) -> Result<()> {
        debug!(
            "Spawned new thread for client on address {}",
            self.stream.peer_addr().unwrap()
        );

        self.ident_exchange()
            .context("Failed during ident exchange")?;

        // First request after ident exchange is always key exchange
        self.client_algorithms = self.key_exchange().context("Failed during key exchange")?;

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
    fn ident_exchange(&mut self) -> Result<()> {
        debug!("--- BEGIN IDENTIFICATION EXCHANGE ---");
        self.send_packet(IDENT_STRING.as_bytes())?;

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
        Ok(())
    }

    fn handle_packet(&mut self) -> Result<Option<DisconnectReason>> {
        let decoded_packet = decode_packet(&self.stream)?;
        self.incoming_packet_sequence += decoded_packet.entire_packet_length;

        let msg_type = u8_to_MessageType(decoded_packet.payload[0])?;
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
                self.key_exchange()?;
            }

            MessageType::SSH_MSG_KEX_ECDH_INIT => {}

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
            .with_context(|| "Failed sending packet")?;

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
