use std::{
    collections::HashMap,
    fs::File,
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
    num: u32,
    window_size: Arc<AtomicU32>,
    initial_window_size: u32,
    max_packet_size: u32,
    pty: Option<Pty>,
}

pub struct Pty {
    pub pair: PtyPair,
    raw_mode: Arc<AtomicBool>,
    envs: HashMap<String, String>,
    stop_pty_thread: Arc<AtomicBool>,
}

pub struct PtyPair {
    pub master: File,
    pub slave: File,
}

impl Pty {
    pub fn new(pair: PtyPair) -> Self {
        Self {
            pair,
            raw_mode: Arc::new(false.into()),
            envs: HashMap::new(),
            stop_pty_thread: Arc::new(false.into()),
        }
    }

    pub fn raw_mode(&self) -> bool {
        self.raw_mode.load(ORDERING)
    }

    pub fn set_is_raw_mode(&self, raw_mode: bool) {
        self.raw_mode.store(raw_mode, ORDERING);
    }

    pub fn should_stop_pty_thread(&self) -> bool {
        self.stop_pty_thread.load(ORDERING)
    }

    /// Sets a flag to stop the pty thread on the next iteration
    pub fn stop_pty_thread(&self) {
        self.stop_pty_thread.store(true, ORDERING);
    }

    pub fn try_clone(&self) -> Result<Self> {
        let pty_fds = PtyPair {
            master: self.pair.master.try_clone()?,
            slave: self.pair.slave.try_clone()?,
        };
        cloexec(&pty_fds.master)?;
        cloexec(&pty_fds.slave)?;

        Ok(Self {
            pair: pty_fds,
            raw_mode: self.raw_mode.clone(),
            envs: self.envs.clone(),
            stop_pty_thread: self.stop_pty_thread.clone(),
        })
    }
}

impl From<OpenptyResult> for PtyPair {
    fn from(value: OpenptyResult) -> Self {
        Self {
            master: File::from(value.master),
            slave: File::from(value.slave),
        }
    }
}

impl Channel {
    pub fn new(num: u32, window_size: u32, max_packet_size: u32) -> Self {
        Self {
            num,
            window_size: Arc::new(window_size.into()),
            initial_window_size: window_size,
            max_packet_size,
            pty: None,
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

    pub const fn pty_initialized(&self) -> bool {
        self.pty.is_some()
    }

    /// Panics if pty_fds isn't initialized
    pub fn pty(&self) -> &Pty {
        self.pty.as_ref().expect("Pty not initialized yet")
    }

    pub fn pty_mut(&mut self) -> &mut Pty {
        self.pty.as_mut().expect("Pty not initialized yet")
    }

    pub fn try_clone(&self) -> Result<Self> {
        let copy = Self {
            num: self.num,
            window_size: self.window_size.clone(),
            initial_window_size: self.initial_window_size,
            max_packet_size: self.max_packet_size,
            pty: match &self.pty {
                Some(pty) => Some(pty.try_clone()?),
                None => None,
            },
        };
        Ok(copy)
    }
}
