use std::thread;

use crate::{
    channel::{Channel, ChannelOpenFailureReason, ChannelRequestType, SESSION_REQUEST},
    decoding::PayloadReader,
    encoding::PacketBuilder,
    types::MessageType,
};
use anyhow::{Context, Result};
use log::{debug, trace};

use super::Session;

// RFC 4254 § 5.1
macro_rules! reject {
    ($msg_type:expr, $session:expr, $channel_num:expr, $reason:expr, $error_msg:expr, $desc:expr) => {
        log::error!("{}", $error_msg);

        let packet = PacketBuilder::new($msg_type, $session)
            .write_u32($channel_num)
            .write_u32($reason as u32)
            .write_string($desc.as_bytes())
            .write_string(b"en")
            .build()?;

        $session.send_packet(&packet)?;
        return Ok(());
    };
}

impl Session {
    // RFC 4254 § 5.1
    pub fn open_channel(&mut self, reader: &mut PayloadReader) -> Result<()> {
        let request_type = reader.next_string_utf8()?;
        trace!("request_type = {}", request_type);

        let sender_channel_num = reader.next_u32()?;
        trace!("sender_channel = {}", sender_channel_num);

        if request_type != SESSION_REQUEST {
            reject!(
                MessageType::SSH_MSG_CHANNEL_OPEN_FAILURE,
                self,
                sender_channel_num,
                ChannelOpenFailureReason::SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                format!("Channel type '{}' not supported", request_type),
                request_type
            );
        }

        let window_size = reader.next_u32()?;
        trace!("window_size = {}", window_size);

        let max_packet_size = reader.next_u32()?;
        trace!("max_packet_size = {}", max_packet_size);

        let recipient_channel_num = sender_channel_num;
        let channel = Channel::new(recipient_channel_num, window_size, max_packet_size);
        self.channels
            .lock()
            .unwrap()
            .insert(recipient_channel_num, channel);

        debug!("Opened channel {}", sender_channel_num);

        let packet = PacketBuilder::new(MessageType::SSH_MSG_CHANNEL_OPEN_CONFIRMATION, self)
            .write_u32(recipient_channel_num)
            .write_u32(sender_channel_num)
            .write_u32(window_size)
            .write_u32(max_packet_size)
            .build()?;
        self.send_packet(&packet)?;

        Ok(())
    }

    pub fn channel_request(&mut self, reader: &mut PayloadReader) -> Result<()> {
        let recipient_chan_num = reader.next_u32()?;
        trace!("channel_number = {}", recipient_chan_num);

        let user_name = self.user_name().clone();

        let channels = self.channels.clone();
        let mut channels = channels.lock().unwrap();
        let channel = channels.get_mut(&recipient_chan_num);

        if let Some(channel) = channel {
            // RFC 4254 § 5.4
            let request_type = reader.next_string_utf8()?;
            debug!("request_type = {}", request_type);

            let want_reply = reader.next_bool()?;
            trace!("want_reply = {}", want_reply);

            match request_type.as_str() {
                ChannelRequestType::PTY_REQ => channel.pty_req(reader)?,
                ChannelRequestType::SHELL => {
                    let mut channel = channel.try_clone().context("Failed to clone channel")?;
                    channel.shell(&user_name)?;

                    let mut session = self.try_clone().context("Failed to clone session")?;
                    thread::spawn::<_, Result<()>>(move || loop {
                        let data = channel.read_terminal()?;
                        let packet =
                            PacketBuilder::new(MessageType::SSH_MSG_CHANNEL_DATA, &session)
                                .write_u32(recipient_chan_num)
                                .write_string(&data)
                                .build()?;
                        channel.send_packet(&packet, &mut session)?;
                    });
                }

                _ => {
                    reject!(
                        MessageType::SSH_MSG_CHANNEL_FAILURE,
                        self,
                        recipient_chan_num,
                        ChannelOpenFailureReason::SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                        format!("Request type '{}' not supported", request_type),
                        request_type
                    );
                }
            }

            if want_reply {
                let packet = PacketBuilder::new(MessageType::SSH_MSG_CHANNEL_SUCCESS, self)
                    .write_u32(recipient_chan_num)
                    .build()?;
                self.send_packet(&packet)?;
            }
        } else {
            reject!(
                MessageType::SSH_MSG_CHANNEL_FAILURE,
                self,
                recipient_chan_num,
                ChannelOpenFailureReason::SSH_OPEN_CONNECT_FAILED,
                format!("Channel num '{}' not found", recipient_chan_num),
                recipient_chan_num.to_string()
            );
        };

        Ok(())
    }
}
