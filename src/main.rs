use std::{net::TcpListener, thread};

use anyhow::{Context, Result};
use const_format::formatcp;
use log::{debug, error};
use session::Session;

mod decoding;
mod encoding;
mod session;
mod types;

pub const IDENT_STRING: &str = formatcp!("SSH-2.0-minisshd_{}\r\n", VERSION);
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PORT: usize = 6969;

fn main() -> Result<()> {
    env_logger::builder().format_target(false).init();
    if let Err(err) = connect() {
        error!("{:?}", err);
    }

    Ok(())
}

fn connect() -> Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", PORT))?;

    for client in listener.incoming() {
        let stream = client.context("Client is invalid")?;
        let client_addr = stream.peer_addr().unwrap();

        let handle = thread::spawn::<_, Result<()>>(|| {
            let mut session = Session::new(stream);
            session.start()?;
            Ok(())
        });

        match handle.join() {
            Ok(val) => match val {
                Ok(()) => debug!("Thread for address {} finished successfully", client_addr),
                Err(err) => error!(
                    "Thread for address {} finished with error: {:?}",
                    client_addr, err
                ),
            },
            Err(_) => error!("Thread for address {} panicked", client_addr),
        }
    }

    Ok(())
}
