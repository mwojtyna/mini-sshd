use std::os::fd::OwnedFd;

use anyhow::{bail, Result};
use log::debug;
use nix::pty::OpenptyResult;
use terminal::cloexec;

use crate::{def_enum, session::Session};

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
    num: u32,
    window_size: u32,
    max_packet_size: u32,
    pty_fds: Option<PtyPair>,
}

pub struct PtyPair {
    master: OwnedFd,
    slave: OwnedFd,
}

impl From<OpenptyResult> for PtyPair {
    fn from(value: OpenptyResult) -> Self {
        PtyPair {
            master: value.master,
            slave: value.slave,
        }
    }
}

impl Channel {
    pub fn new(num: u32, window_size: u32, max_packet_size: u32) -> Self {
        Channel {
            num,
            window_size,
            max_packet_size,
            pty_fds: None,
        }
    }

    pub fn send_packet(&mut self, packet: &[u8], session: &mut Session) -> Result<()> {
        if packet.len() > self.max_packet_size as usize {
            bail!(
                "Packet length {} exceeds max_packet_size {}",
                packet.len(),
                self.max_packet_size
            );
        }

        session.send_packet(packet)?;
        self.window_size -= packet.len() as u32;
        debug!(
            "Sent packet from channel {}, window_size reduced to {}",
            self.num, self.window_size
        );

        Ok(())
    }

    fn pty_fds(&self) -> &PtyPair {
        self.pty_fds.as_ref().expect("Pty not initialized yet")
    }

    pub fn try_clone(&self) -> Result<Self> {
        let pty_fds = PtyPair {
            master: self.pty_fds().master.try_clone()?,
            slave: self.pty_fds().slave.try_clone()?,
        };
        cloexec(&pty_fds.master)?;
        cloexec(&pty_fds.slave)?;

        let clone = Channel {
            num: self.num,
            window_size: self.window_size,
            max_packet_size: self.max_packet_size,
            pty_fds: Some(pty_fds),
        };
        Ok(clone)
    }
}
