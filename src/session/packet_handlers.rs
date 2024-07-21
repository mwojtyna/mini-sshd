use crate::{
    decoding::{DecodedPacket, PayloadReader},
    encoding::PacketBuilder,
    types::{DisconnectReason, HostKeyAlgorithm, MessageType, ServiceName},
};
use anyhow::Result;
use log::{debug, warn};

use super::Session;

pub struct PacketHandlerArgs {
    pub reader: PayloadReader,
    pub msg_type: MessageType,
    pub packet: DecodedPacket,
}

/// `Ok(None)` means the packet was handled successfully and the session should continue.
/// `Ok(Some(disconnect_reason))` means the packet was handled successfully and the session should be closed with `disconnect_reason`.
/// `Err(err)` means the packet was not handled successfully and the session should be closed.
pub type PacketHandlerFn =
    fn(session: &mut Session, handler_args: PacketHandlerArgs) -> Result<Option<DisconnectReason>>;

pub const not_set: PacketHandlerFn = |_, args| {
    warn!("Handler for message type '{:?}' not set", args.msg_type);
    Ok(None)
};

pub const disconnect: PacketHandlerFn =
    |_, _| Ok(Some(DisconnectReason::SSH_DISCONNECT_BY_APPLICATION));

pub const ignore: PacketHandlerFn = |_, _| Ok(None);

pub const unimplemented: PacketHandlerFn = |_, mut args| {
    let sequence_num = args.reader.next_u32()?;
    warn!(
        "Client responded with '{:?}' for packet sent with sequence num = {}",
        MessageType::SSH_MSG_UNIMPLEMENTED,
        sequence_num
    );
    Ok(None)
};

pub const algorithm_negotiation: PacketHandlerFn = |session, mut args| {
    session.algorithm_negotiation(&args.packet, &mut args.reader)?;

    session.set_packet_handler(MessageType::SSH_MSG_KEX_ECDH_INIT, key_exchange);
    Ok(None)
};

pub const key_exchange: PacketHandlerFn =
    |session, mut args| match session.key_exchange(&mut args.reader) {
        Ok((k, h)) => {
            session.compute_secrets(k, h)?;

            session.set_packet_handler(MessageType::SSH_MSG_NEWKEYS, new_keys);
            Ok(None)
        }
        Err(_) => Ok(Some(DisconnectReason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED)),
    };

pub const new_keys: PacketHandlerFn = |session, _| {
    let packet = PacketBuilder::new(MessageType::SSH_MSG_NEWKEYS, session).build()?;
    session.send_packet(&packet)?;
    session.kex.finished = true;

    // RFC 8308 § 2.3, 2.4
    // Advertise extensions
    if session.kex().ext_info_c {
        let packet = PacketBuilder::new(MessageType::SSH_MSG_EXT_INFO, session)
            .write_u32(1)
            .write_string(b"server-sig-algs")
            .write_name_list(HostKeyAlgorithm::VARIANTS)
            .build()?;
        session.send_packet(&packet)?;
    }

    session.set_packet_handler(MessageType::SSH_MSG_SERVICE_REQUEST, service_request);
    Ok(None)
};

pub const service_request: PacketHandlerFn = |session, mut args| {
    // RFC 4253 § 10
    debug!("--- BEGIN SERVICE REQUEST ---");

    let service_name = args.reader.next_string_utf8()?;
    debug!("service_name = {}", service_name);

    if service_name == ServiceName::SSH_USERAUTH {
        let packet = PacketBuilder::new(MessageType::SSH_MSG_SERVICE_ACCEPT, session)
            .write_string(service_name.as_bytes())
            .build()?;
        session.send_packet(&packet)?;
    } else {
        return Ok(Some(DisconnectReason::SSH_DISCONNECT_SERVICE_NOT_AVAILABLE));
    }

    session.set_packet_handler(MessageType::SSH_MSG_USERAUTH_REQUEST, userauth);
    debug!("--- END SERVICE REQUEST ---");
    Ok(None)
};

pub const userauth: PacketHandlerFn = |session, mut args| {
    session.userauth(&mut args.reader)?;

    session.set_packet_handler(MessageType::SSH_MSG_CHANNEL_OPEN, channel_open);
    Ok(None)
};

pub const channel_open: PacketHandlerFn = |session, mut args| {
    session.open_channel(&mut args.reader)?;

    session.set_packet_handler(MessageType::SSH_MSG_CHANNEL_REQUEST, channel_request);
    session.set_packet_handler(MessageType::SSH_MSG_CHANNEL_EOF, channel_eof);
    session.set_packet_handler(MessageType::SSH_MSG_CHANNEL_CLOSE, channel_close);
    Ok(None)
};

pub const channel_eof: PacketHandlerFn = |_, _| Ok(None);

pub const channel_close: PacketHandlerFn = |session, _| {
    session.close();
    Ok(None)
};

pub const channel_request: PacketHandlerFn = |session, mut args| {
    session.channel_request(&mut args.reader)?;

    session.set_packet_handler(MessageType::SSH_MSG_CHANNEL_DATA, channel_data);
    session.set_packet_handler(
        MessageType::SSH_MSG_CHANNEL_WINDOW_ADJUST,
        channel_window_adjust,
    );
    Ok(None)
};

pub const channel_data: PacketHandlerFn = |session, mut args| {
    session.channel_data(&mut args.reader)?;
    Ok(None)
};

pub const channel_window_adjust: PacketHandlerFn = |session, mut args| {
    session.channel_window_adjust(&mut args.reader)?;
    Ok(None)
};
