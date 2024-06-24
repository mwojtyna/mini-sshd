use crate::{decoding::PayloadReader, def_enum, encoding::PacketBuilder, types::MessageType};
use anyhow::Result;
use log::{debug, error, trace};

use super::Session;

pub struct Channel {
    pub chan_type: String,
    pub window_size: u32,
    pub max_packet_size: u32,
}

def_enum!(pub ChannelType => &'static str {
    SESSION => "session",
    PTY_REQ => "pty-req",
    X11_REQ => "x11-req",
    X11 => "x11",
    ENV => "env",
    SHELL => "shell",
    EXEC => "exec",
    SUBSYSTEM => "subsystem"
});

#[allow(non_camel_case_types, dead_code)]
pub enum ChannelOpenFailureReason {
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
    SSH_OPEN_CONNECT_FAILED = 2,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
    SSH_OPEN_RESOURCE_SHORTAGE = 4,
}

impl<'session_impl> Session<'session_impl> {
    // RFC 4254 § 5.1
    pub fn open_channel(&mut self, reader: &mut PayloadReader) -> Result<()> {
        let chan_type = reader.next_string_utf8()?;
        trace!("channel_type = {}", chan_type);

        let sender_channel = reader.next_u32()?;
        trace!("sender_channel = {}", sender_channel);

        if !ChannelType::VARIANTS.contains(&chan_type.as_str()) {
            reject_with_err(
                self,
                sender_channel,
                ChannelOpenFailureReason::SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                &format!("Channel type '{}' not supported", chan_type),
            )?;
            return Ok(());
        }

        let window_size = reader.next_u32()?;
        trace!("window_size = {}", window_size);

        let max_packet_size = reader.next_u32()?;
        trace!("max_packet_size = {}", max_packet_size);

        let recipient_channel = sender_channel;
        let channel = Channel {
            chan_type,
            window_size,
            max_packet_size,
        };
        self.channels.insert(recipient_channel, channel);

        debug!("Opened channel {}", sender_channel);

        let packet = PacketBuilder::new(MessageType::SSH_MSG_CHANNEL_OPEN_CONFIRMATION, self)
            .write_u32(recipient_channel)
            .write_u32(sender_channel)
            .write_u32(window_size)
            .write_u32(max_packet_size)
            .build()?;
        self.send_packet(&packet)?;

        Ok(())
    }

    pub fn channel_request(&mut self, reader: &mut PayloadReader) -> Result<()> {
        Ok(())
    }
}

// RFC 4254 § 5.1
fn reject(session: &mut Session, channel_nr: u32, reason: ChannelOpenFailureReason) -> Result<()> {
    let packet = PacketBuilder::new(MessageType::SSH_MSG_CHANNEL_OPEN_FAILURE, session)
        .write_u32(channel_nr)
        .write_u32(reason as u32)
        .write_string(b"")
        .write_string(b"en")
        .build()?;
    session.send_packet(&packet)?;

    Ok(())
}
fn reject_with_err(
    session: &mut Session,
    channel_nr: u32,
    reason: ChannelOpenFailureReason,
    error_msg: &str,
) -> Result<()> {
    error!("{}", error_msg);
    reject(session, channel_nr, reason)?;
    Ok(())
}
