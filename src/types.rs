use enum_iterator::Sequence;
use num_derive::FromPrimitive;
use openssl::{hash::MessageDigest, nid::Nid, symm::Cipher};

use crate::def_enum;

#[allow(non_camel_case_types)]
#[derive(FromPrimitive, Debug, PartialEq, Clone, Copy, Sequence, Hash, Eq)]
pub enum MessageType {
    // Transport layer protocol:
    // 1 to 19 - Transport layer generic (e.g., disconnect, ignore, debug, etc.)
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_IGNORE = 2,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_DEBUG = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,
    SSH_MSG_EXT_INFO = 7,

    // 20 to 29 - Algorithm negotiation
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,

    // 30 to 49 - Key exchange method specific (numbers can be reused for different authentication methods)
    SSH_MSG_KEX_ECDH_INIT = 30,
    SSH_MSG_KEX_ECDH_REPLY = 31,

    // User authentication protocol:
    // 50 to 59 - User authentication generic
    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,

    // 60 to 79 - User authentication method specific (numbers can be reused for different authentication methods)
    SSH_MSG_USERAUTH_PK_OK = 60,

    // Connection protocol:
    // 80 to 89 - Connection protocol generic
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_REQUEST_SUCCESS = 81,
    SSH_MSG_REQUEST_FAILURE = 82,

    // 90 to 127 - Channel related messages
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_CLOSE = 97,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
    SSH_MSG_CHANNEL_FAILURE = 100,
    // Reserved for client protocols:
    // 128 to 191 - Reserved

    // Local extensions:
    // 192 to 255 - Local extensions
}

#[allow(non_camel_case_types, dead_code)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DisconnectReason {
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1,
    SSH_DISCONNECT_PROTOCOL_ERROR = 2,
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
    SSH_DISCONNECT_RESERVED = 4,
    SSH_DISCONNECT_MAC_ERROR = 5,
    SSH_DISCONNECT_COMPRESSION_ERROR = 6,
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
    SSH_DISCONNECT_CONNECTION_LOST = 10,
    SSH_DISCONNECT_BY_APPLICATION = 11,
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12,
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13,
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
    SSH_DISCONNECT_ILLEGAL_USER_NAME = 15,
}

#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(FromPrimitive, Debug, PartialEq, Eq, Hash, Sequence)]
pub enum TerminalOpCode {
    /// Indicates end of options.
    TTY_OP_END = 0,
    /// Interrupt character; 255 if none.  Similarly for the other characters.  Not all of these characters are supported on all systems.
    VINTR = 1,
    /// The quit character (sends SIGQUIT signal on POSIX systems).
    VQUIT = 2,
    /// Erase the character to left of the cursor.
    VERASE = 3,
    /// Kill the current input line.
    VKILL = 4,
    /// End-of-file character (sends EOF from the terminal).
    VEOF = 5,
    /// End-of-line character in addition to carriage return and/or linefeed.
    VEOL = 6,
    /// Additional end-of-line character.
    VEOL2 = 7,
    /// Continues paused output (normally control-Q).
    VSTART = 8,
    /// Pauses output (normally control-S).
    VSTOP = 9,
    /// Suspends the current program.
    VSUSP = 10,
    /// Another suspend character.
    VDSUSP = 11,
    /// Reprints the current input line.
    VREPRINT = 12,
    /// Erases a word left of cursor.
    VWERASE = 13,
    /// Enter the next character typed literally, even if it is a special character
    VLNEXT = 14,
    /// Character to flush output.
    VFLUSH = 15,
    /// Switch to a different shell layer.
    VSWTCH = 16,
    /// Prints system status line (load, command, pid, etc).
    VSTATUS = 17,
    /// Toggles the flushing of terminal output.
    VDISCARD = 18,
    /// The ignore parity flag.  The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is TRUE.
    IGNPAR = 30,
    /// Mark parity and framing errors.
    PARMRK = 31,
    /// Enable checking of parity errors.
    INPCK = 32,
    /// Strip 8th bit off characters.
    ISTRIP = 33,
    /// Map NL into CR on input.
    INLCR = 34,
    /// Ignore CR on input.
    IGNCR = 35,
    /// Map CR to NL on input.
    ICRNL = 36,
    /// Translate uppercase characters to lowercase.
    IUCLC = 37,
    /// Enable output flow control.
    IXON = 38,
    /// Any char will restart after stop.
    IXANY = 39,
    /// Enable input flow control.
    IXOFF = 40,
    /// Ring bell on input queue full.
    IMAXBEL = 41,
    /// Terminal input and output is assumed to be encoded in UTF-8. [RFC](https://datatracker.ietf.org/doc/html/rfc8160)
    IUTF8 = 42,
    /// Enable signals INTR, QUIT, [D]SUSP.
    ISIG = 50,
    /// Canonicalize input lines.
    ICANON = 51,
    /// Enable input and output of uppercase characters by preceding their lowercase equivalents with "\".
    XCASE = 52,
    /// Enable echoing.
    ECHO = 53,
    /// Visually erase chars.
    ECHOE = 54,
    /// Kill character discards current line.
    ECHOK = 55,
    /// Echo NL even if ECHO is off.
    ECHONL = 56,
    /// Don't flush after interrupt.
    NOFLSH = 57,
    /// Stop background jobs from output.
    TOSTOP = 58,
    /// Enable extensions.
    IEXTEN = 59,
    /// Echo control characters as ^(Char).
    ECHOCTL = 60,
    /// Visual erase for line kill.
    ECHOKE = 61,
    /// Retype pending input.
    PENDIN = 62,
    /// Enable output processing.
    OPOST = 70,
    /// Convert lowercase to uppercase.
    OLCUC = 71,
    /// Map NL to CR-NL.
    ONLCR = 72,
    /// Translate carriage return to newline (output).
    OCRNL = 73,
    /// Translate newline to carriage return-newline (output).
    ONOCR = 74,
    /// Newline performs a carriage return (output).
    ONLRET = 75,
    /// 7 bit mode.
    CS7 = 90,
    /// 8 bit mode.
    CS8 = 91,
    /// Parity enable.
    PARENB = 92,
    /// Odd parity, else even.
    PARODD = 93,
    /// Specifies the input baud rate in bits per second.
    TTY_OP_ISPEED = 128,
    /// Specifies the output baud rate in bits per second.
    TTY_OP_OSPEED = 129,
}

def_enum!(pub KexAlgorithm => &'static str {
    ECDH_SHA2_NISTP256 => "ecdh-sha2-nistp256",
    ECDH_SHA2_NISTP384 => "ecdh-sha2-nistp384",
    ECDH_SHA2_NISTP521 => "ecdh-sha2-nistp521",
    // RFC 8308 § 2.1
    EXT_INFO_C => "ext-info-c",
});
#[derive(Clone)]
pub struct KexAlgorithmDetails {
    pub hash: MessageDigest,
    pub curve: Nid,
}

def_enum!(pub HostKeyAlgorithm => &'static str {
    ECDSA_SHA2_NISTP256 => "ecdsa-sha2-nistp256",
    ECDSA_SHA2_NISTP384 => "ecdsa-sha2-nistp384",
    ECDSA_SHA2_NISTP521 => "ecdsa-sha2-nistp521",
});
#[derive(Clone)]
pub struct HostKeyAlgorithmDetails {
    pub hash: MessageDigest,
    pub curve: Nid,
}

def_enum!(pub EncryptionAlgorithm => &'static str {
    AES128_CTR => "aes128-ctr",
});
#[derive(Clone)]
pub struct EncryptionAlgorithmDetails {
    pub cipher: Cipher,
    pub block_size: usize,
}

def_enum!(pub HmacAlgorithm => &'static str {
   HMAC_SHA2_256 => "hmac-sha2-256",
});
#[derive(Clone)]
pub struct HmacAlgorithmDetails {
    pub hash: MessageDigest,
}

def_enum!(pub CompressionAlgorithm => &'static str {
    NONE => "none",
});
#[derive(Clone)]
pub struct CompressionAlgorithmDetails {}

def_enum!(pub ServiceName => &'static str {
    SSH_USERAUTH => "ssh-userauth",
    // SSH_CONNECTION => "ssh-connection",
});
