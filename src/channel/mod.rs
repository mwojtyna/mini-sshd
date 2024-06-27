use nix::pty::OpenptyResult;

use crate::def_enum;

pub mod terminal;

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

pub struct Channel {
    window_size: u32,
    max_packet_size: u32,
    pty_fds: Option<OpenptyResult>,
}

impl Channel {
    pub fn new(window_size: u32, max_packet_size: u32) -> Self {
        Channel {
            window_size,
            max_packet_size,
            pty_fds: None,
        }
    }

    pub fn pty_fds(&self) -> &OpenptyResult {
        self.pty_fds.as_ref().expect("Pty not initialized yet")
    }
}
