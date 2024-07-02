use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

use algorithm_negotiation::Algorithms;
use anyhow::{bail, Context, Result};
use enum_iterator::all;
use log::{debug, error, info, trace};
use packet_handlers::{PacketHandlerArgs, PacketHandlerFn};
use pretty_hex::pretty_hex;

use crate::{
    channel::Channel,
    crypto::Crypto,
    decoding::{decode_packet, PayloadReader},
    encoding::PacketBuilder,
    types::{DisconnectReason, MessageType},
    ServerConfig,
};

pub mod algorithm_negotiation;
pub mod channel;
pub mod compute_secrets;
pub mod key_exchange;
#[allow(non_upper_case_globals)]
pub mod packet_handlers;
pub mod userauth;

pub struct Session<'session> {
    stream: TcpStream,
    server_sequence_number: u32,
    client_sequence_number: u32,

    server_config: &'session ServerConfig,
    algorithms: Option<Algorithms>,
    crypto: Option<Crypto>,

    packet_handlers: HashMap<MessageType, PacketHandlerFn>,
    kex: KeyExchange,
    user_name: Option<String>,
    channels: HashMap<u32, Channel>,

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
    pub ext_info_c: bool,
}

impl<'session_impl> Session<'session_impl> {
    pub fn new(stream: TcpStream, server_config: &'session_impl ServerConfig) -> Self {
        let iter = all::<MessageType>()
            .map::<(MessageType, PacketHandlerFn), _>(|t| (t, packet_handlers::not_set));

        let mut packet_handlers: HashMap<MessageType, PacketHandlerFn> = HashMap::from_iter(iter);
        packet_handlers.insert(MessageType::SSH_MSG_DISCONNECT, packet_handlers::disconnect);
        packet_handlers.insert(MessageType::SSH_MSG_IGNORE, packet_handlers::ignore);
        packet_handlers.insert(
            MessageType::SSH_MSG_UNIMPLEMENTED,
            packet_handlers::unimplemented,
        );
        packet_handlers.insert(MessageType::SSH_MSG_DEBUG, packet_handlers::ignore);

        Session {
            stream,
            server_sequence_number: 0,
            client_sequence_number: 0,

            server_config,
            algorithms: None,
            crypto: None,

            packet_handlers,
            kex: KeyExchange::default(),
            user_name: None,
            channels: HashMap::new(),

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
    pub fn start(&'session_impl mut self) -> Result<()> {
        info!(
            "Created new session for client on address {}",
            self.stream.peer_addr().unwrap()
        );

        let mut reader = BufReader::new(self.stream.try_clone()?);

        self.kex.client_ident = self
            .ident_exchange(&mut reader)
            .context("Failed during ident exchange")?;

        self.set_packet_handler(
            MessageType::SSH_MSG_KEXINIT,
            packet_handlers::algorithm_negotiation,
        );

        loop {
            let disconnect = self
                .handle_packet(&mut reader)
                .context("Failed handling packet")?;
            if let Some(reason) = disconnect {
                self.disconnect(reason)?;
                break;
            }
            self.client_sequence_number = self.client_sequence_number.wrapping_add(1);
        }

        Ok(())
    }

    pub fn server_sequence_number(&self) -> u32 {
        self.server_sequence_number
    }

    pub fn client_sequence_number(&self) -> u32 {
        self.client_sequence_number
    }

    /// Panics if algorithms have not been negotiated yet
    pub fn algorithms(&self) -> &Algorithms {
        self.algorithms
            .as_ref()
            .expect("Algorithms not negotiated yet")
    }

    /// Panics if algorithms have not been negotiated yet
    pub fn crypto(&self) -> &Crypto {
        self.crypto
            .as_ref()
            .expect("Crypto not initialized yet, algorithms have not been negotiated")
    }

    pub fn kex(&self) -> &KeyExchange {
        &self.kex
    }

    pub fn user_name(&self) -> String {
        self.user_name.clone().expect("Userauth not completed yet")
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

    pub fn set_packet_handler(&mut self, msg_type: MessageType, handler: PacketHandlerFn) {
        self.packet_handlers.insert(msg_type, handler);
    }

    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.stream
            .write_all(packet)
            .context("Failed sending packet")?;
        trace!("Packet sent");

        self.server_sequence_number = self.server_sequence_number().wrapping_add(1);

        Ok(())
    }

    // RFC 4253 § 4.2
    fn ident_exchange(&mut self, reader: &mut BufReader<TcpStream>) -> Result<String> {
        self.send_packet(format!("{}\r\n", self.server_config.ident_string).as_bytes())?;
        self.server_sequence_number = 0; // Sequence number doesn't increment for ident exchange

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
                    bail!("Unsupported protocol version of {:?}", proto_version);
                }
            } else {
                self.disconnect(DisconnectReason::SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED)?;
                bail!("Could not parse protocol version '{:?}'", proto_version_str);
            }
        } else {
            self.disconnect(DisconnectReason::SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED)?;
            bail!(
                "Could not find protocol version in client ident string of '{:?}'",
                client_ident
            );
        }

        Ok(client_ident)
    }

    fn handle_packet(
        &mut self,
        reader: &mut BufReader<TcpStream>,
    ) -> Result<Option<DisconnectReason>> {
        let packet = decode_packet(self, reader)?;
        let msg_type = packet.message_type()?;
        debug!(
            "Received message of type = {:?}, server_sequence_number = {}, client_sequence_number = {}",
            msg_type, self.server_sequence_number(), self.client_sequence_number()
        );

        let reader = PayloadReader::new(packet.payload());
        let handler: Option<&PacketHandlerFn> = self.packet_handlers.get(&msg_type);

        if let Some(handler) = handler {
            let args = PacketHandlerArgs {
                reader,
                msg_type,
                packet,
            };
            handler(self, args)?;
        } else {
            error!(
                "Unhandled message type.\ntype: {:?}\npayload:\n{}",
                msg_type,
                pretty_hex(&packet.payload())
            );

            let packet = PacketBuilder::new(MessageType::SSH_MSG_UNIMPLEMENTED, self)
                .write_u32(self.server_sequence_number())
                .build()?;
            self.send_packet(&packet)?;
        }

        Ok(None)
    }

    // RFC 4253 § 11.1
    fn disconnect(&mut self, reason: DisconnectReason) -> Result<()> {
        let packet = PacketBuilder::new(MessageType::SSH_MSG_DISCONNECT, self)
            .write_byte(reason as u8)
            .write_bytes(b"")
            .write_bytes(b"en")
            .build()?;
        self.send_packet(&packet)?;

        debug!("Disconnecting because of {:?}", reason);
        Ok(())
    }
}
