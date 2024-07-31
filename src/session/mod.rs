use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, RwLock,
    },
};

use algorithm_negotiation::Algorithms;
use anyhow::{bail, Context, Result};
use enum_iterator::all;
use log::{debug, error, info, trace, warn};
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

const ORDERING: Ordering = Ordering::Relaxed;

pub struct Session {
    stream: TcpStream,
    is_closed: bool,
    server_sequence_number: Arc<AtomicU32>,
    client_sequence_number: Arc<AtomicU32>,
    server_config: &'static ServerConfig,
    packet_handlers: Arc<Mutex<HashMap<MessageType, PacketHandlerFn>>>,

    algorithms: Option<Arc<Algorithms>>,
    crypto: Option<Arc<RwLock<Crypto>>>,
    kex: KeyExchange,
    user_name: Option<Arc<String>>,
    channels: Arc<Mutex<HashMap<u32, Channel>>>,
    secrets: Option<Arc<Secrets>>,
}

#[derive(Default, Clone)]
pub struct KeyExchange {
    pub client_ident: String,
    pub client_kexinit_payload: Vec<u8>,
    pub server_kexinit_payload: Vec<u8>,
    pub finished: bool,
    pub ext_info_c: bool,
}

#[derive(Debug)]
pub struct Secrets {
    pub session_id: Vec<u8>,
    pub iv_client_server: Vec<u8>,
    pub iv_server_client: Vec<u8>,
    pub enc_key_client_server: Vec<u8>,
    pub enc_key_server_client: Vec<u8>,
    pub integrity_key_client_server: Vec<u8>,
    pub integrity_key_server_client: Vec<u8>,
}

impl Session {
    pub fn new(stream: TcpStream, server_config: &'static ServerConfig) -> Self {
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

        Self {
            stream,
            is_closed: false,
            server_sequence_number: Arc::new(0.into()),
            client_sequence_number: Arc::new(0.into()),
            server_config,
            packet_handlers: Arc::new(packet_handlers.into()),

            algorithms: None,
            crypto: None,
            kex: KeyExchange::default(),
            user_name: None,
            channels: Arc::new(Mutex::new(HashMap::new())),
            secrets: None,
        }
    }

    /// This will handle all incoming packets, blocking this thread until disconnect.
    pub fn start(&mut self) -> Result<()> {
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
            if self.is_closed {
                info!(
                    "Session for client on address {} closed",
                    self.stream.peer_addr().unwrap(),
                );
                return Ok(());
            }

            let disconnect = self
                .handle_packet(&mut reader)
                .context("Failed handling packet")?;
            if let Some(reason) = disconnect {
                self.disconnect(reason)?;
                break;
            }
            self.client_sequence_number.fetch_add(1, ORDERING);
        }

        Ok(())
    }

    pub fn close(&mut self) {
        self.is_closed = true;
    }

    pub fn server_sequence_number(&self) -> u32 {
        self.server_sequence_number.load(ORDERING)
    }

    pub fn client_sequence_number(&self) -> u32 {
        self.client_sequence_number.load(ORDERING)
    }

    pub fn set_packet_handler(&self, msg_type: MessageType, handler: PacketHandlerFn) {
        self.packet_handlers
            .lock()
            .unwrap()
            .insert(msg_type, handler);
    }

    /// Panics if algorithms have not been negotiated yet
    pub fn algorithms(&self) -> &Algorithms {
        self.algorithms
            .as_ref()
            .expect("Algorithms not negotiated yet")
    }

    /// Panics if algorithms have not been negotiated yet
    pub fn crypto(&self) -> &Arc<RwLock<Crypto>> {
        self.crypto
            .as_ref()
            .expect("Crypto not initialized yet, algorithms have not been negotiated")
    }

    /// Panics if algorithms have not been negotiated yet
    pub fn crypto_mut(&mut self) -> &mut Arc<RwLock<Crypto>> {
        self.crypto
            .as_mut()
            .expect("Crypto not initialized yet, algorithms have not been negotiated")
    }

    pub const fn kex(&self) -> &KeyExchange {
        &self.kex
    }

    /// Panics if user_name not set yet
    pub fn user_name(&self) -> &Arc<String> {
        self.user_name.as_ref().expect("User name not set yet")
    }

    /// Panics if secrets not computed yet
    pub fn secrets(&self) -> &Arc<Secrets> {
        self.secrets.as_ref().expect("Secrets not computed yet")
    }

    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.stream
            .write_all(packet)
            .context("Failed sending packet")?;
        trace!("Packet sent");

        self.server_sequence_number.fetch_add(1, ORDERING);

        Ok(())
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            stream: self.stream.try_clone()?,
            is_closed: self.is_closed,
            server_sequence_number: self.server_sequence_number.clone(),
            client_sequence_number: self.client_sequence_number.clone(),
            server_config: self.server_config,
            packet_handlers: self.packet_handlers.clone(),

            algorithms: self.algorithms.clone(),
            crypto: self.crypto.clone(),
            kex: self.kex.clone(),
            user_name: self.user_name.clone(),
            channels: self.channels.clone(),
            secrets: self.secrets.clone(),
        })
    }

    // RFC 4253 § 4.2
    fn ident_exchange(&mut self, reader: &mut BufReader<TcpStream>) -> Result<String> {
        self.send_packet(format!("{}\r\n", self.server_config.ident_string).as_bytes())?;
        self.server_sequence_number = Arc::new(0.into()); // Sequence number doesn't increment for ident exchange

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
            "Received message of type = {:?}, server_sequence_number = {:?}, client_sequence_number = {:?}",
            msg_type, self.server_sequence_number, self.client_sequence_number
        );

        let reader = PayloadReader::new(packet.payload());

        let handler = self.packet_handlers.lock().unwrap().get(&msg_type).copied();
        if let Some(handler) = handler {
            let args = PacketHandlerArgs {
                reader,
                msg_type,
                packet,
            };

            let reason = handler(self, args)?;
            if let Some(reason) = reason {
                return Ok(Some(reason));
            }
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

        warn!("Disconnecting because of {:?}", reason);
        Ok(())
    }
}
