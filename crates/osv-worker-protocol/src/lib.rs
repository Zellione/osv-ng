//! Allocation-bounded wire protocol shared by isolated workers and their broker.

use std::{error::Error, fmt};
use zeroize::Zeroize;

pub const MAGIC: [u8; 8] = *b"OSVWIPC\0";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 24;
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024;
pub const MAX_DATA_LEN: usize = MAX_PAYLOAD_LEN - 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Ready = 2,
    Start = 3,
    Data = 4,
    End = 5,
    Cancel = 6,
    Complete = 7,
    Failed = 8,
}

impl TryFrom<u8> for Kind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Start),
            4 => Ok(Self::Data),
            5 => Ok(Self::End),
            6 => Ok(Self::Cancel),
            7 => Ok(Self::Complete),
            8 => Ok(Self::Failed),
            _ => Err(ProtocolError::UnknownKind),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub request_id: u64,
    pub message: Message,
}

#[derive(Clone, Eq, PartialEq)]
pub enum Message {
    Hello { minimum: u16, maximum: u16 },
    Ready { version: u16, sandbox_flags: u32 },
    Start { role: Role },
    Data { sequence: u64, bytes: Vec<u8> },
    End { chunks: u64 },
    Cancel,
    Complete,
    Failed { class: FailureClass },
}

impl fmt::Debug for Message {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello { minimum, maximum } => formatter
                .debug_struct("Hello")
                .field("minimum", minimum)
                .field("maximum", maximum)
                .finish(),
            Self::Ready {
                version,
                sandbox_flags,
            } => formatter
                .debug_struct("Ready")
                .field("version", version)
                .field("sandbox_flags", sandbox_flags)
                .finish(),
            Self::Start { role } => formatter.debug_struct("Start").field("role", role).finish(),
            Self::Data { sequence, bytes } => formatter
                .debug_struct("Data")
                .field("sequence", sequence)
                .field("bytes", &format_args!("[REDACTED; {}]", bytes.len()))
                .finish(),
            Self::End { chunks } => formatter
                .debug_struct("End")
                .field("chunks", chunks)
                .finish(),
            Self::Cancel => formatter.write_str("Cancel"),
            Self::Complete => formatter.write_str("Complete"),
            Self::Failed { class } => formatter
                .debug_struct("Failed")
                .field("class", class)
                .finish(),
        }
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        if let Self::Data { bytes, .. } = self {
            bytes.as_mut_slice().zeroize();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    Media = 1,
    Archive = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FailureClass {
    InvalidInput = 1,
    ResourceLimit = 2,
    Internal = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    BadMagic,
    UnsupportedVersion,
    Oversized,
    Truncated,
    UnknownKind,
    Malformed,
    InvalidTransition,
    WrongRequest,
    OutOfSequence,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BadMagic => "invalid worker protocol magic",
            Self::UnsupportedVersion => "unsupported worker protocol version",
            Self::Oversized => "worker protocol frame exceeds its limit",
            Self::Truncated => "truncated worker protocol frame",
            Self::UnknownKind => "unknown worker protocol message",
            Self::Malformed => "malformed worker protocol message",
            Self::InvalidTransition => "invalid worker protocol transition",
            Self::WrongRequest => "worker protocol request identity changed",
            Self::OutOfSequence => "worker protocol data sequence is invalid",
        })
    }
}

impl Error for ProtocolError {}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let (kind, payload) = encode_message(&self.message)?;
        let payload_len = u32::try_from(payload.len()).map_err(|_| ProtocolError::Oversized)?;
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(ProtocolError::Oversized);
        }
        let mut encoded = Vec::with_capacity(HEADER_LEN + payload.len());
        encoded.extend_from_slice(&MAGIC);
        encoded.extend_from_slice(&VERSION.to_le_bytes());
        encoded.push(kind as u8);
        encoded.push(0);
        encoded.extend_from_slice(&payload_len.to_le_bytes());
        encoded.extend_from_slice(&self.request_id.to_le_bytes());
        encoded.extend_from_slice(&payload);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() < HEADER_LEN {
            return Err(ProtocolError::Truncated);
        }
        if encoded[..8] != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        if u16::from_le_bytes([encoded[8], encoded[9]]) != VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if encoded[11] != 0 {
            return Err(ProtocolError::Malformed);
        }
        let length = u32::from_le_bytes(encoded[12..16].try_into().expect("fixed slice")) as usize;
        if length > MAX_PAYLOAD_LEN {
            return Err(ProtocolError::Oversized);
        }
        if encoded.len() != HEADER_LEN + length {
            return Err(ProtocolError::Truncated);
        }
        let kind = Kind::try_from(encoded[10])?;
        let request_id = u64::from_le_bytes(encoded[16..24].try_into().expect("fixed slice"));
        Ok(Self {
            request_id,
            message: decode_message(kind, &encoded[HEADER_LEN..])?,
        })
    }
}

fn encode_message(message: &Message) -> Result<(Kind, Vec<u8>), ProtocolError> {
    let result = match message {
        Message::Hello { minimum, maximum } => {
            let mut bytes = Vec::with_capacity(4);
            bytes.extend_from_slice(&minimum.to_le_bytes());
            bytes.extend_from_slice(&maximum.to_le_bytes());
            (Kind::Hello, bytes)
        }
        Message::Ready {
            version,
            sandbox_flags,
        } => {
            let mut bytes = Vec::with_capacity(6);
            bytes.extend_from_slice(&version.to_le_bytes());
            bytes.extend_from_slice(&sandbox_flags.to_le_bytes());
            (Kind::Ready, bytes)
        }
        Message::Start { role } => (Kind::Start, vec![*role as u8]),
        Message::Data { sequence, bytes } => {
            if bytes.len() > MAX_DATA_LEN {
                return Err(ProtocolError::Oversized);
            }
            let mut payload = Vec::with_capacity(8 + bytes.len());
            payload.extend_from_slice(&sequence.to_le_bytes());
            payload.extend_from_slice(bytes);
            (Kind::Data, payload)
        }
        Message::End { chunks } => (Kind::End, chunks.to_le_bytes().to_vec()),
        Message::Cancel => (Kind::Cancel, Vec::new()),
        Message::Complete => (Kind::Complete, Vec::new()),
        Message::Failed { class } => (Kind::Failed, vec![*class as u8]),
    };
    Ok(result)
}

fn decode_message(kind: Kind, bytes: &[u8]) -> Result<Message, ProtocolError> {
    Ok(match kind {
        Kind::Hello if bytes.len() == 4 => Message::Hello {
            minimum: u16::from_le_bytes(bytes[..2].try_into().expect("fixed slice")),
            maximum: u16::from_le_bytes(bytes[2..].try_into().expect("fixed slice")),
        },
        Kind::Ready if bytes.len() == 6 => Message::Ready {
            version: u16::from_le_bytes(bytes[..2].try_into().expect("fixed slice")),
            sandbox_flags: u32::from_le_bytes(bytes[2..].try_into().expect("fixed slice")),
        },
        Kind::Start if bytes.len() == 1 => Message::Start {
            role: match bytes[0] {
                1 => Role::Media,
                2 => Role::Archive,
                _ => return Err(ProtocolError::Malformed),
            },
        },
        Kind::Data if bytes.len() >= 8 => Message::Data {
            sequence: u64::from_le_bytes(bytes[..8].try_into().expect("fixed slice")),
            bytes: bytes[8..].to_vec(),
        },
        Kind::End if bytes.len() == 8 => Message::End {
            chunks: u64::from_le_bytes(bytes.try_into().expect("fixed slice")),
        },
        Kind::Cancel if bytes.is_empty() => Message::Cancel,
        Kind::Complete if bytes.is_empty() => Message::Complete,
        Kind::Failed if bytes.len() == 1 => Message::Failed {
            class: match bytes[0] {
                1 => FailureClass::InvalidInput,
                2 => FailureClass::ResourceLimit,
                3 => FailureClass::Internal,
                _ => return Err(ProtocolError::Malformed),
            },
        },
        _ => return Err(ProtocolError::Malformed),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerState {
    AwaitingReady,
    Ready,
    Streaming { next_sequence: u64 },
    AwaitingResult,
    Finished,
}

#[derive(Debug)]
pub struct BrokerMachine {
    request_id: u64,
    state: BrokerState,
}

impl BrokerMachine {
    pub fn new(request_id: u64) -> Self {
        Self {
            request_id,
            state: BrokerState::AwaitingReady,
        }
    }

    pub fn state(&self) -> BrokerState {
        self.state
    }

    pub fn sent(&mut self, frame: &Frame) -> Result<(), ProtocolError> {
        self.check_request(frame)?;
        self.state = match (self.state, &frame.message) {
            (BrokerState::AwaitingReady, Message::Hello { minimum, maximum })
                if *minimum <= VERSION && *maximum >= VERSION =>
            {
                BrokerState::AwaitingReady
            }
            (BrokerState::Ready, Message::Start { .. }) => {
                BrokerState::Streaming { next_sequence: 0 }
            }
            (BrokerState::Streaming { next_sequence }, Message::Data { sequence, .. })
                if *sequence == next_sequence =>
            {
                BrokerState::Streaming {
                    next_sequence: next_sequence + 1,
                }
            }
            (BrokerState::Streaming { next_sequence }, Message::End { chunks })
                if *chunks == next_sequence =>
            {
                BrokerState::AwaitingResult
            }
            (BrokerState::Streaming { .. } | BrokerState::AwaitingResult, Message::Cancel) => {
                BrokerState::Finished
            }
            _ => return Err(ProtocolError::InvalidTransition),
        };
        Ok(())
    }

    pub fn received(&mut self, frame: &Frame) -> Result<(), ProtocolError> {
        self.check_request(frame)?;
        self.state = match (self.state, &frame.message) {
            (
                BrokerState::AwaitingReady,
                Message::Ready {
                    version: VERSION, ..
                },
            ) => BrokerState::Ready,
            (BrokerState::AwaitingResult, Message::Complete | Message::Failed { .. }) => {
                BrokerState::Finished
            }
            _ => return Err(ProtocolError::InvalidTransition),
        };
        Ok(())
    }

    fn check_request(&self, frame: &Frame) -> Result<(), ProtocolError> {
        if frame.request_id == self.request_id {
            Ok(())
        } else {
            Err(ProtocolError::WrongRequest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_messages_round_trip() {
        let messages = [
            Message::Hello {
                minimum: 1,
                maximum: 1,
            },
            Message::Ready {
                version: 1,
                sandbox_flags: 7,
            },
            Message::Start { role: Role::Media },
            Message::Data {
                sequence: 3,
                bytes: vec![1, 2, 3],
            },
            Message::End { chunks: 4 },
            Message::Cancel,
            Message::Complete,
            Message::Failed {
                class: FailureClass::InvalidInput,
            },
        ];
        for message in messages {
            let frame = Frame {
                request_id: 42,
                message,
            };
            assert_eq!(Frame::decode(&frame.encode().unwrap()).unwrap(), frame);
        }
    }

    #[test]
    fn decoder_rejects_every_truncation_and_oversized_claim() {
        let encoded = Frame {
            request_id: 7,
            message: Message::Data {
                sequence: 0,
                bytes: vec![9; 32],
            },
        }
        .encode()
        .unwrap();
        for end in 0..encoded.len() {
            assert!(Frame::decode(&encoded[..end]).is_err());
        }
        let mut oversized = encoded;
        oversized[12..16].copy_from_slice(&((MAX_PAYLOAD_LEN as u32) + 1).to_le_bytes());
        assert_eq!(Frame::decode(&oversized), Err(ProtocolError::Oversized));
    }

    #[test]
    fn state_machine_binds_identity_sequence_and_negotiation() {
        let mut machine = BrokerMachine::new(9);
        machine
            .sent(&Frame {
                request_id: 9,
                message: Message::Hello {
                    minimum: 1,
                    maximum: 1,
                },
            })
            .unwrap();
        machine
            .received(&Frame {
                request_id: 9,
                message: Message::Ready {
                    version: 1,
                    sandbox_flags: 0,
                },
            })
            .unwrap();
        machine
            .sent(&Frame {
                request_id: 9,
                message: Message::Start {
                    role: Role::Archive,
                },
            })
            .unwrap();
        assert_eq!(
            machine.sent(&Frame {
                request_id: 9,
                message: Message::Data {
                    sequence: 1,
                    bytes: vec![]
                }
            }),
            Err(ProtocolError::InvalidTransition)
        );
        assert_eq!(
            machine.sent(&Frame {
                request_id: 8,
                message: Message::Data {
                    sequence: 0,
                    bytes: vec![]
                }
            }),
            Err(ProtocolError::WrongRequest)
        );
    }

    #[test]
    fn data_debug_never_exposes_plaintext() {
        let message = Message::Data {
            sequence: 0,
            bytes: b"sensitive-pixels".to_vec(),
        };
        let debug = format!("{message:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("sensitive-pixels"));
    }
}
