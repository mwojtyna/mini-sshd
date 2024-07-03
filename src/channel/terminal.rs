use std::{
    fs::File,
    io::{BufReader, Read},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};
use enum_iterator::all;
use log::{debug, trace};
use nix::{
    fcntl::{fcntl, FcntlArg, FdFlag},
    ioctl_write_int_bad,
    libc::{
        TIOCSCTTY, VDISCARD, VEOF, VEOL, VEOL2, VERASE, VINTR, VKILL, VLNEXT, VQUIT, VREPRINT,
        VSTART, VSTOP, VSUSP, VWERASE,
    },
    pty::{openpty, Winsize},
    sys::termios::{
        cfsetispeed, cfsetospeed, tcgetattr, tcsetattr, BaudRate, ControlFlags, InputFlags,
        LocalFlags, OutputFlags, SetArg,
    },
    unistd::{setsid, write, User},
};
use num_traits::FromPrimitive;

use crate::{
    decoding::{u8_array_to_u32, u8_to_bool, PayloadReader},
    types::TerminalOpCode,
};

use super::Channel;

#[derive(Debug)]
pub struct TerminalMode {
    pub opcode: TerminalOpCode,
    pub arg: u32,
}

impl Channel {
    // RFC 4254 § 6.2
    pub fn pty_req(&mut self, reader: &mut PayloadReader) -> Result<()> {
        let term = reader.next_string_utf8()?;
        let width_ch = reader.next_u32()? as u16;
        let height_ch = reader.next_u32()? as u16;
        let width_px = reader.next_u32()? as u16;
        let height_px = reader.next_u32()? as u16;
        let modes_blob = reader.next_string()?;

        // https://man7.org/linux/man-pages/man2/TIOCSWINSZ.2const.html
        let winsize = Winsize {
            ws_row: if height_ch > 0 { height_ch } else { height_px },
            ws_col: if width_ch > 0 { width_ch } else { width_px },
            ws_xpixel: 0, // unused
            ws_ypixel: 0, // unused
        };
        let modes = decode_terminal_modes(&modes_blob)?;

        debug!("term = {}", term);
        debug!("width_ch = {}", width_ch);
        debug!("height_ch = {}", height_ch);
        debug!("width_px = {}", width_px);
        debug!("height_px = {}", height_px);
        trace!("modes_blob = {:?}", modes_blob);
        trace!("modes = {:?}", modes);

        let result = openpty(&winsize, None)?;
        cloexec(&result.master)?;
        cloexec(&result.slave)?;
        set_terminal_modes(&result.slave, &modes).context("Failed settings terminal modes")?;
        debug!(
            "Opened pty with fds: master = {}, slave = {}",
            result.master.as_raw_fd(),
            result.slave.as_raw_fd()
        );

        self.pty_fds = Some(result.into());

        Ok(())
    }

    pub fn shell(&self, user_name: &str) -> Result<()> {
        let user = User::from_name(user_name)?
            .context(format!("User with name {:?} not found", user_name))?;
        trace!("user = {:?}", user);

        let slave_fd = &self.pty_fds().slave;
        let slave_raw_fd = slave_fd.as_raw_fd();
        // Login shell must have '-' prepended to shell executable
        let arg0 = "-".to_owned()
            + user
                .shell
                .to_string_lossy()
                .rsplit('/')
                .next()
                .context("Invalid shell path")?;

        let stdin = fd_to_stdio(slave_fd);
        let stdout = fd_to_stdio(slave_fd);
        let stderr = fd_to_stdio(slave_fd);

        let child = unsafe {
            Command::new(&user.shell)
                .arg0(arg0)
                .current_dir(user.dir)
                .env_clear()
                .env("SHELL", &user.shell)
                .envs(std::env::vars_os())
                .uid(user.uid.as_raw())
                .gid(user.gid.as_raw())
                .stdin(stdin)
                .stdout(stdout)
                .stderr(stderr)
                .pre_exec(move || {
                    setsid()?;

                    ioctl_write_int_bad!(tiocsctty, TIOCSCTTY);
                    tiocsctty(slave_raw_fd, 0)?;

                    Ok(())
                })
                .spawn()?
        };
        debug!("Opened shell {:?} with pid {:?}", user.shell, child.id());

        Ok(())
    }

    pub fn read_terminal(&self, reader: &mut BufReader<File>) -> Result<Vec<u8>> {
        let mut buf = vec![0; self.max_packet_size as usize - 512]; // 0.5KB less than max packet size to account for packet length, padding
        let amount = reader.read(&mut buf)?;

        Ok(buf[..amount].to_vec())
    }

    pub fn write_terminal(&mut self, data: &[u8]) -> Result<()> {
        let fd = &self.pty_fds().master;
        write(fd, data)?;

        Ok(())
    }
}

pub fn cloexec<F: AsRawFd>(fd: &F) -> Result<()> {
    let flags_set = fcntl(fd.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    if flags_set == -1 {
        bail!("Failed to set cloexec on fd '{}'", fd.as_raw_fd());
    }

    Ok(())
}

fn decode_terminal_modes(encoded_modes: &[u8]) -> Result<Vec<TerminalMode>> {
    let modes_len = all::<TerminalOpCode>()
        .collect::<Vec<TerminalOpCode>>()
        .len();
    let mut modes = Vec::with_capacity(modes_len);
    let reader = &mut encoded_modes.iter();

    loop {
        let opcode = reader.next().context("Terminal modes buffer corrupt")?;
        let opcode =
            TerminalOpCode::from_u8(*opcode).context(format!("Opcode {} not supported", opcode))?;

        if opcode == TerminalOpCode::TTY_OP_END {
            trace!("Finished terminal mode decoding");
            break;
        }

        let arg_bytes: Vec<u8> = reader.take(4).copied().collect();
        let arg = u8_array_to_u32(&arg_bytes)?;

        modes.push(TerminalMode { opcode, arg });
    }

    Ok(modes)
}

fn set_terminal_modes<F: AsFd + Copy>(fd: F, modes: &Vec<TerminalMode>) -> Result<()> {
    let mut termios = tcgetattr(fd)?;

    for mode in modes {
        // Some codes are not supported on Linux
        // https://man7.org/linux/man-pages/man3/termios.3.html
        match mode.opcode {
            TerminalOpCode::TTY_OP_END => bail!(
                "TTY_OP_END appeared in terminal modes after decoding, this should never happen"
            ),
            TerminalOpCode::VINTR => {
                termios.control_chars[VINTR] = mode.arg as u8;
            }
            TerminalOpCode::VQUIT => {
                termios.control_chars[VQUIT] = mode.arg as u8;
            }
            TerminalOpCode::VERASE => {
                termios.control_chars[VERASE] = mode.arg as u8;
            }
            TerminalOpCode::VKILL => {
                termios.control_chars[VKILL] = mode.arg as u8;
            }
            TerminalOpCode::VEOF => {
                termios.control_chars[VEOF] = mode.arg as u8;
            }
            TerminalOpCode::VEOL => {
                termios.control_chars[VEOL] = mode.arg as u8;
            }
            TerminalOpCode::VEOL2 => {
                termios.control_chars[VEOL2] = mode.arg as u8;
            }
            TerminalOpCode::VSTART => {
                termios.control_chars[VSTART] = mode.arg as u8;
            }
            TerminalOpCode::VSTOP => {
                termios.control_chars[VSTOP] = mode.arg as u8;
            }
            TerminalOpCode::VSUSP => {
                termios.control_chars[VSUSP] = mode.arg as u8;
            }
            TerminalOpCode::VDSUSP => {}
            TerminalOpCode::VREPRINT => {
                termios.control_chars[VREPRINT] = mode.arg as u8;
            }
            TerminalOpCode::VWERASE => {
                termios.control_chars[VWERASE] = mode.arg as u8;
            }
            TerminalOpCode::VLNEXT => {
                termios.control_chars[VLNEXT] = mode.arg as u8;
            }
            TerminalOpCode::VFLUSH => {}
            TerminalOpCode::VSWTCH => {}
            TerminalOpCode::VSTATUS => {}
            TerminalOpCode::VDISCARD => {
                termios.control_chars[VDISCARD] = mode.arg as u8;
            }

            TerminalOpCode::IGNPAR => termios
                .input_flags
                .set(InputFlags::IGNPAR, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::PARMRK => termios
                .input_flags
                .set(InputFlags::PARMRK, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::INPCK => termios
                .input_flags
                .set(InputFlags::INPCK, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ISTRIP => termios
                .input_flags
                .set(InputFlags::ISTRIP, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::INLCR => termios
                .input_flags
                .set(InputFlags::INLCR, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::IGNCR => termios
                .input_flags
                .set(InputFlags::IGNCR, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ICRNL => termios
                .input_flags
                .set(InputFlags::ICRNL, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::IUCLC => {}
            TerminalOpCode::IXON => termios
                .input_flags
                .set(InputFlags::IXON, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::IXANY => termios
                .input_flags
                .set(InputFlags::IXANY, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::IXOFF => termios
                .input_flags
                .set(InputFlags::IXOFF, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::IMAXBEL => termios
                .input_flags
                .set(InputFlags::IMAXBEL, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::IUTF8 => termios
                .input_flags
                .set(InputFlags::IUTF8, u8_to_bool(mode.arg as u8)?),

            TerminalOpCode::ISIG => termios
                .local_flags
                .set(LocalFlags::ISIG, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ICANON => termios
                .local_flags
                .set(LocalFlags::ICANON, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::XCASE => {}
            TerminalOpCode::ECHO => termios
                .local_flags
                .set(LocalFlags::ECHO, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ECHOE => termios
                .local_flags
                .set(LocalFlags::ECHOE, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ECHOK => termios
                .local_flags
                .set(LocalFlags::ECHOK, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ECHONL => termios
                .local_flags
                .set(LocalFlags::ECHONL, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::NOFLSH => termios
                .local_flags
                .set(LocalFlags::NOFLSH, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::TOSTOP => termios
                .local_flags
                .set(LocalFlags::TOSTOP, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::IEXTEN => termios
                .local_flags
                .set(LocalFlags::IEXTEN, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ECHOCTL => termios
                .local_flags
                .set(LocalFlags::ECHOCTL, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ECHOKE => termios
                .local_flags
                .set(LocalFlags::ECHOKE, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::PENDIN => termios
                .local_flags
                .set(LocalFlags::PENDIN, u8_to_bool(mode.arg as u8)?),

            TerminalOpCode::OPOST => termios
                .output_flags
                .set(OutputFlags::OPOST, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::OLCUC => termios
                .output_flags
                .set(OutputFlags::OLCUC, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ONLCR => termios
                .output_flags
                .set(OutputFlags::ONLCR, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::OCRNL => termios
                .output_flags
                .set(OutputFlags::OCRNL, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ONOCR => termios
                .output_flags
                .set(OutputFlags::ONOCR, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::ONLRET => termios
                .output_flags
                .set(OutputFlags::ONLRET, u8_to_bool(mode.arg as u8)?),

            TerminalOpCode::CS7 => termios
                .control_flags
                .set(ControlFlags::CS7, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::CS8 => termios
                .control_flags
                .set(ControlFlags::CS8, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::PARENB => termios
                .control_flags
                .set(ControlFlags::PARENB, u8_to_bool(mode.arg as u8)?),
            TerminalOpCode::PARODD => termios
                .control_flags
                .set(ControlFlags::PARODD, u8_to_bool(mode.arg as u8)?),

            TerminalOpCode::TTY_OP_ISPEED => cfsetispeed(&mut termios, u32_to_BaudRate(mode.arg)?)?,
            TerminalOpCode::TTY_OP_OSPEED => cfsetospeed(&mut termios, u32_to_BaudRate(mode.arg)?)?,
        }
    }

    tcsetattr(fd, SetArg::TCSANOW, &termios)?;

    Ok(())
}

fn fd_to_stdio<F: AsRawFd>(fd: &F) -> Stdio {
    unsafe { Stdio::from_raw_fd(fd.as_raw_fd()) }
}

#[allow(non_snake_case)]
fn u32_to_BaudRate(value: u32) -> Result<BaudRate> {
    let baud_rate = match value {
        0 => BaudRate::B0,
        50 => BaudRate::B50,
        75 => BaudRate::B75,
        110 => BaudRate::B110,
        134 => BaudRate::B134,
        150 => BaudRate::B150,
        200 => BaudRate::B200,
        300 => BaudRate::B300,
        600 => BaudRate::B600,
        1200 => BaudRate::B1200,
        1800 => BaudRate::B1800,
        2400 => BaudRate::B2400,
        4800 => BaudRate::B4800,
        9600 => BaudRate::B9600,
        19200 => BaudRate::B19200,
        38400 => BaudRate::B38400,
        57600 => BaudRate::B57600,
        115200 => BaudRate::B115200,
        230400 => BaudRate::B230400,
        460800 => BaudRate::B460800,
        500000 => BaudRate::B500000,
        576000 => BaudRate::B576000,
        921600 => BaudRate::B921600,
        1000000 => BaudRate::B1000000,
        1152000 => BaudRate::B1152000,
        1500000 => BaudRate::B1500000,
        2000000 => BaudRate::B2000000,
        2500000 => BaudRate::B2500000,
        3000000 => BaudRate::B3000000,
        3500000 => BaudRate::B3500000,
        4000000 => BaudRate::B4000000,

        _ => bail!("Invalid baud rate of {}", value),
    };

    Ok(baud_rate)
}
