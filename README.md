# mini-sshd
A minimal SSH server implementation written from scratch in Rust, largely compliant with the protocol standards outlined in RFCs 4250-4254.

Tested on Linux with OpenSSH client version >= `8.9`.

## Configuration
 - `RUST_LOG` environment variable should be set to enable logging levels: `error`, `warn`, `info`, `debug`, `trace`<br>
  > [!WARNING]  
  > `trace` level logs secrets
 - Authorized public keys should be placed in `~/.ssh/authorized_keys`. Format is the same as in OpenSSH (one public key per line)
 - Server host keys are automatically generated on first start and saved in `$XDG_DATA_HOME/mini-sshd`

## Supported authentication methods
 - public key

## Supported algorithms
### Key exchange
 - ecdh-sha2-nistp256
 - ecdh-sha2-nistp384
 - ecdh-sha2-nistp521

### Host key
 - ecdsa-sha2-nistp256
 - ecdsa-sha2-nistp384
 - ecdsa-sha2-nistp512

### Encryption
 - aes-128-ctr

### MAC
 - hmac-sha2-256
