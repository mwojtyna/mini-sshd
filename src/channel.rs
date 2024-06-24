use anyhow::Result;
use log::trace;

use crate::{decoding::PayloadReader, def_enum};

pub const SESSION_REQUEST: &str = "session";
def_enum!(pub ChannelRequestType => &'static str {
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

#[derive(Debug)]
pub struct Channel {
    pub window_size: u32,
    pub max_packet_size: u32,
}

impl Channel {
    pub fn new(window_size: u32, max_packet_size: u32) -> Self {
        Channel {
            window_size,
            max_packet_size,
        }
    }

    pub fn pty_req(&self, reader: &mut PayloadReader) -> Result<()> {
        let env = reader.next_string_utf8()?;
        let width_ch = reader.next_u32()?;
        let height_ch = reader.next_u32()?;
        let width_px = reader.next_u32()?;
        let height_px = reader.next_u32()?;
        let modes = reader.next_string()?;

        trace!("env = {}", env);
        trace!("width_ch = {}", width_ch);
        trace!("height_ch = {}", height_ch);
        trace!("width_px = {}", width_px);
        trace!("height_px = {}", height_px);
        trace!("modes = {:?}", modes);

        Ok(())
    }
}
