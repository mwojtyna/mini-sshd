use std::{
    os::fd::OwnedFd,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
};

use anyhow::{bail, Result};
use log::debug;
use nix::pty::OpenptyResult;
use terminal::cloexec;

use crate::{def_enum, encoding::PacketBuilder, session::Session, types::MessageType};

pub mod terminal;

pub const SESSION_REQUEST: &str = "session";
def_enum!(pub ChannelRequestType => &'static str {
    PTY_REQ => "pty-req",
    X11_REQ => "x11-req",
    X11 => "x11",
    ENV => "env",
    SHELL => "shell",
    EXEC => "exec",
    SUBSYSTEM => "subsystem",
    WINDOW_CHANGE => "window-change"
});

#[allow(non_camel_case_types, dead_code)]
pub enum ChannelOpenFailureReason {
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
    SSH_OPEN_CONNECT_FAILED = 2,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
    SSH_OPEN_RESOURCE_SHORTAGE = 4,
}

const ORDERING: Ordering = Ordering::Relaxed;

pub struct Channel {
    pub pty_fds: Option<PtyPair>,
    pub pty_raw_mode: Arc<AtomicBool>,

    num: u32,
    window_size: Arc<AtomicU32>,
    initial_window_size: u32,
    max_packet_size: u32,
}

pub struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

impl From<OpenptyResult> for PtyPair {
    fn from(value: OpenptyResult) -> Self {
        Self {
            master: value.master,
            slave: value.slave,
        }
    }
}

impl Channel {
    pub fn new(num: u32, window_size: u32, max_packet_size: u32) -> Self {
        Self {
            pty_fds: None,
            pty_raw_mode: Arc::new(false.into()),

            num,
            window_size: Arc::new(window_size.into()),
            initial_window_size: window_size,
            max_packet_size,
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

        if self.window_size() < packet.len() as u32 {
            let packet = PacketBuilder::new(MessageType::SSH_MSG_CHANNEL_WINDOW_ADJUST, session)
                .write_u32(self.num)
                .write_u32(self.initial_window_size)
                .build()?;
            session.send_packet(&packet)?;
            self.increase_window_size(self.initial_window_size)?;
        }

        session.send_packet(packet)?;
        self.decrease_window_size(packet.len() as u32);

        debug!(
            "Sent packet from channel {}, window_size = {:?}",
            self.num, self.window_size
        );

        Ok(())
    }

    pub fn window_size(&self) -> u32 {
        self.window_size.load(ORDERING)
    }

    pub fn decrease_window_size(&mut self, size: u32) {
        if self.window_size() > size {
            self.window_size.fetch_sub(size, ORDERING);
        }
    }

    pub fn increase_window_size(&mut self, size: u32) -> Result<()> {
        let prev = self.window_size();
        self.window_size.fetch_add(size, ORDERING);

        if self.window_size() < prev {
            bail!(
                "Channel {} window overflow after increasing window size",
                self.num
            );
        }

        Ok(())
    }

    pub fn pty_fds(&self) -> &PtyPair {
        self.pty_fds.as_ref().expect("Pty not initialized yet")
    }

    pub fn pty_raw_mode(&self) -> bool {
        self.pty_raw_mode.load(ORDERING)
    }

    pub fn set_pty_raw_mode(&self, raw_mode: bool) {
        self.pty_raw_mode.store(raw_mode, ORDERING);
    }

    pub fn try_clone(&self) -> Result<Self> {
        let pty_fds = PtyPair {
            master: self.pty_fds().master.try_clone()?,
            slave: self.pty_fds().slave.try_clone()?,
        };
        cloexec(&pty_fds.master)?;
        cloexec(&pty_fds.slave)?;

        let copy = Self {
            pty_fds: Some(pty_fds),
            pty_raw_mode: self.pty_raw_mode.clone(),

            num: self.num,
            window_size: self.window_size.clone(),
            initial_window_size: self.initial_window_size,
            max_packet_size: self.max_packet_size,
        };
        Ok(copy)
    }
}
