use std::{net::TcpListener, thread};

use anyhow::{Context, Result};
use crypto::{generate_host_key, HostKey};
use log::{debug, error};
use session::{algorithm_negotiation::AlgorithmNegotiation, Session};

mod crypto;
mod decoding;
mod encoding;
mod session;
mod types;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PORT: usize = 6969;

#[derive(Clone)]
pub struct ServerConfig {
    algorithms: AlgorithmNegotiation,
    host_key: HostKey,
    ident_string: String,
}

fn main() -> Result<()> {
    env_logger::builder().format_target(false).init();
    if let Err(err) = connect() {
        error!("{:?}", err);
    }

    Ok(())
}

fn connect() -> Result<()> {
    let server_config = ServerConfig {
        algorithms: AlgorithmNegotiation {
            // RFC 9142 § 4
            kex_algorithms: vec![
                "ecdh-sha2-nistp256".to_owned(),
                "ecdh-sha2-nistp381".to_owned(),
                "ecdh-sha2-nistp521".to_owned(),
            ],

            // RFC 5656 § 10.1
            server_host_key_algorithms: vec!["ecdsa-sha2-nistp256".to_owned()],
            encryption_algorithms_client_to_server: vec!["aes128-ctr".to_owned()],
            encryption_algorithms_server_to_client: vec!["aes128-ctr".to_owned()],

            // RFC 6668 § 2
            mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_owned()],
            mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_owned()],

            compression_algorithms_client_to_server: vec!["none".to_owned()],
            compression_algorithms_server_to_client: vec!["none".to_owned()],
            languages_client_to_server: vec!["".to_owned()],
            languages_server_to_client: vec!["".to_owned()],
        },
        host_key: generate_host_key().context("Failed creating host key")?,
        ident_string: format!("SSH-2.0-minisshd_{}", VERSION),
    };

    if cfg!(debug_assertions) {
        debug!(
            "public_key: {:?}",
            String::from_utf8(server_config.host_key.public_key_pem.to_vec())
                .unwrap()
                .lines()
                .nth(1)
                .unwrap()
        );
        debug!(
            "private_key: {:?}",
            String::from_utf8(server_config.host_key.private_key_pem.to_vec())
                .unwrap()
                .lines()
                .nth(1)
                .unwrap()
        );
    }

    let listener = TcpListener::bind(format!("127.0.0.1:{}", PORT))?;

    for client in listener.incoming() {
        let stream = client.context("Client is invalid")?;
        let client_addr = stream.peer_addr().unwrap();
        let server_config = server_config.clone();

        let handle = thread::spawn::<_, Result<()>>(|| {
            let mut session = Session::new(stream, server_config);
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
