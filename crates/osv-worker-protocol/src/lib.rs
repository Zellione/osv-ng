//! Allocation-bounded wire protocol shared by isolated workers and their broker.

use osv_crypto::SecretBytes;
use std::{error::Error, fmt};

pub const MAGIC: [u8; 8] = *b"OSVWIPC\0";
pub const VERSION: u16 = 2;
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

#[derive(Debug, Eq, PartialEq)]
pub struct Frame {
    pub request_id: u64,
    pub message: Message,
}

#[derive(Eq, PartialEq)]
pub enum Message {
    Hello {
        minimum: u16,
        maximum: u16,
    },
    Ready {
        version: u16,
        sandbox_flags: u32,
        page_locks: osv_crypto::LockStatus,
    },
    Start {
        role: Role,
    },
    Data {
        sequence: u64,
        bytes: SecretBytes,
    },
    End {
        chunks: u64,
    },
    Cancel,
    Complete {
        page_locks: osv_crypto::LockStatus,
    },
    Failed {
        class: FailureClass,
        page_locks: osv_crypto::LockStatus,
    },
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
                page_locks,
            } => formatter
                .debug_struct("Ready")
                .field("version", version)
                .field("sandbox_flags", sandbox_flags)
                .field("page_locks", page_locks)
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
            Self::Complete { page_locks } => formatter
                .debug_struct("Complete")
                .field("page_locks", page_locks)
                .finish(),
            Self::Failed { class, page_locks } => formatter
                .debug_struct("Failed")
                .field("class", class)
                .field("page_locks", page_locks)
                .finish(),
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
    Memory,
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
            Self::Memory => "worker protocol protected allocation failed",
        })
    }
}

impl Error for ProtocolError {}

impl Frame {
    #[must_use]
    pub fn lock_status(&self) -> osv_crypto::LockStatus {
        match &self.message {
            Message::Data { bytes, .. } => bytes.lock_status(),
            _ => osv_crypto::LockStatus::Locked,
        }
    }

    pub fn encoded_len(&self) -> Result<usize, ProtocolError> {
        HEADER_LEN
            .checked_add(payload_len(&self.message)?)
            .ok_or(ProtocolError::Oversized)
    }

    pub fn encode_into(&self, encoded: &mut [u8]) -> Result<(), ProtocolError> {
        let payload_len = payload_len(&self.message)?;
        if encoded.len() != HEADER_LEN + payload_len {
            return Err(ProtocolError::Truncated);
        }
        let payload_len = u32::try_from(payload_len).map_err(|_| ProtocolError::Oversized)?;
        if payload_len as usize > MAX_PAYLOAD_LEN {
            return Err(ProtocolError::Oversized);
        }
        encoded[..8].copy_from_slice(&MAGIC);
        encoded[8..10].copy_from_slice(&VERSION.to_le_bytes());
        encoded[10] = message_kind(&self.message) as u8;
        encoded[11] = 0;
        encoded[12..16].copy_from_slice(&payload_len.to_le_bytes());
        encoded[16..24].copy_from_slice(&self.request_id.to_le_bytes());
        encode_payload(&self.message, &mut encoded[HEADER_LEN..]);
        Ok(())
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

fn payload_len(message: &Message) -> Result<usize, ProtocolError> {
    match message {
        Message::Hello { .. } => Ok(4),
        Message::Ready { .. } => Ok(7),
        Message::Start { .. } => Ok(1),
        Message::Failed { .. } => Ok(2),
        Message::Data { bytes, .. } if bytes.len() <= MAX_DATA_LEN => Ok(8 + bytes.len()),
        Message::Data { .. } => Err(ProtocolError::Oversized),
        Message::End { .. } => Ok(8),
        Message::Cancel => Ok(0),
        Message::Complete { .. } => Ok(1),
    }
}

fn message_kind(message: &Message) -> Kind {
    match message {
        Message::Hello { .. } => Kind::Hello,
        Message::Ready { .. } => Kind::Ready,
        Message::Start { .. } => Kind::Start,
        Message::Data { .. } => Kind::Data,
        Message::End { .. } => Kind::End,
        Message::Cancel => Kind::Cancel,
        Message::Complete { .. } => Kind::Complete,
        Message::Failed { .. } => Kind::Failed,
    }
}

fn encode_payload(message: &Message, payload: &mut [u8]) {
    match message {
        Message::Hello { minimum, maximum } => {
            payload[..2].copy_from_slice(&minimum.to_le_bytes());
            payload[2..].copy_from_slice(&maximum.to_le_bytes());
        }
        Message::Ready {
            version,
            sandbox_flags,
            page_locks,
        } => {
            payload[..2].copy_from_slice(&version.to_le_bytes());
            payload[2..6].copy_from_slice(&sandbox_flags.to_le_bytes());
            payload[6] = encode_lock_status(*page_locks);
        }
        Message::Start { role } => payload[0] = *role as u8,
        Message::Data { sequence, bytes } => {
            payload[..8].copy_from_slice(&sequence.to_le_bytes());
            payload[8..].copy_from_slice(bytes.expose());
        }
        Message::End { chunks } => payload.copy_from_slice(&chunks.to_le_bytes()),
        Message::Failed { class, page_locks } => {
            payload[0] = *class as u8;
            payload[1] = encode_lock_status(*page_locks);
        }
        Message::Complete { page_locks } => payload[0] = encode_lock_status(*page_locks),
        Message::Cancel => {}
    }
}

fn decode_message(kind: Kind, bytes: &[u8]) -> Result<Message, ProtocolError> {
    Ok(match kind {
        Kind::Hello if bytes.len() == 4 => Message::Hello {
            minimum: u16::from_le_bytes(bytes[..2].try_into().expect("fixed slice")),
            maximum: u16::from_le_bytes(bytes[2..].try_into().expect("fixed slice")),
        },
        Kind::Ready if bytes.len() == 7 => Message::Ready {
            version: u16::from_le_bytes(bytes[..2].try_into().expect("fixed slice")),
            sandbox_flags: u32::from_le_bytes(bytes[2..6].try_into().expect("fixed slice")),
            page_locks: decode_lock_status(bytes[6])?,
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
            bytes: SecretBytes::new(&bytes[8..]).map_err(|_| ProtocolError::Memory)?,
        },
        Kind::End if bytes.len() == 8 => Message::End {
            chunks: u64::from_le_bytes(bytes.try_into().expect("fixed slice")),
        },
        Kind::Cancel if bytes.is_empty() => Message::Cancel,
        Kind::Complete if bytes.len() == 1 => Message::Complete {
            page_locks: decode_lock_status(bytes[0])?,
        },
        Kind::Failed if bytes.len() == 2 => Message::Failed {
            class: match bytes[0] {
                1 => FailureClass::InvalidInput,
                2 => FailureClass::ResourceLimit,
                3 => FailureClass::Internal,
                _ => return Err(ProtocolError::Malformed),
            },
            page_locks: decode_lock_status(bytes[1])?,
        },
        _ => return Err(ProtocolError::Malformed),
    })
}

const fn encode_lock_status(status: osv_crypto::LockStatus) -> u8 {
    match status {
        osv_crypto::LockStatus::Locked => 1,
        osv_crypto::LockStatus::Degraded => 2,
    }
}

fn decode_lock_status(value: u8) -> Result<osv_crypto::LockStatus, ProtocolError> {
    match value {
        1 => Ok(osv_crypto::LockStatus::Locked),
        2 => Ok(osv_crypto::LockStatus::Degraded),
        _ => Err(ProtocolError::Malformed),
    }
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
            (BrokerState::AwaitingResult, Message::Complete { .. } | Message::Failed { .. }) => {
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
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };
    use zeroize::Zeroize;

    struct CountingAllocator;

    std::thread_local! {
        static COUNT_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
        static ALLOCATION_COUNT: Cell<usize> = const { Cell::new(0) };
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    #[allow(unsafe_code)]
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            COUNT_ALLOCATIONS.with(|enabled| {
                if enabled.get() {
                    ALLOCATION_COUNT.with(|count| count.set(count.get() + 1));
                }
            });
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) };
        }
    }

    #[test]
    fn all_messages_round_trip() {
        let messages = [
            Message::Hello {
                minimum: VERSION,
                maximum: VERSION,
            },
            Message::Ready {
                version: VERSION,
                sandbox_flags: 7,
                page_locks: osv_crypto::LockStatus::Locked,
            },
            Message::Start { role: Role::Media },
            Message::Data {
                sequence: 3,
                bytes: SecretBytes::new(&[1, 2, 3]).unwrap(),
            },
            Message::End { chunks: 4 },
            Message::Cancel,
            Message::Complete {
                page_locks: osv_crypto::LockStatus::Locked,
            },
            Message::Failed {
                class: FailureClass::InvalidInput,
                page_locks: osv_crypto::LockStatus::Degraded,
            },
        ];
        for message in messages {
            let frame = Frame {
                request_id: 42,
                message,
            };
            let mut encoded = vec![0; frame.encoded_len().unwrap()];
            frame.encode_into(&mut encoded).unwrap();
            assert_eq!(Frame::decode(&encoded).unwrap(), frame);
        }
    }

    #[test]
    fn decoder_rejects_every_truncation_and_oversized_claim() {
        let frame = Frame {
            request_id: 7,
            message: Message::Data {
                sequence: 0,
                bytes: SecretBytes::new(&[9; 32]).unwrap(),
            },
        };
        let mut encoded = vec![0; frame.encoded_len().unwrap()];
        frame.encode_into(&mut encoded).unwrap();
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
                    minimum: VERSION,
                    maximum: VERSION,
                },
            })
            .unwrap();
        machine
            .received(&Frame {
                request_id: 9,
                message: Message::Ready {
                    version: VERSION,
                    sandbox_flags: 0,
                    page_locks: osv_crypto::LockStatus::Locked,
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
                    bytes: SecretBytes::new(&[]).unwrap()
                }
            }),
            Err(ProtocolError::InvalidTransition)
        );
        assert_eq!(
            machine.sent(&Frame {
                request_id: 8,
                message: Message::Data {
                    sequence: 0,
                    bytes: SecretBytes::new(&[]).unwrap()
                }
            }),
            Err(ProtocolError::WrongRequest)
        );
    }

    #[test]
    fn data_debug_never_exposes_plaintext() {
        let message = Message::Data {
            sequence: 0,
            bytes: SecretBytes::new(b"sensitive-pixels").unwrap(),
        };
        let debug = format!("{message:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("sensitive-pixels"));
    }

    #[test]
    fn data_encoding_creates_no_intermediate_allocation() {
        let frame = Frame {
            request_id: 17,
            message: Message::Data {
                sequence: 3,
                bytes: SecretBytes::new(&[0xa5; 4096]).unwrap(),
            },
        };
        let mut encoded = vec![0; frame.encoded_len().unwrap()];
        ALLOCATION_COUNT.with(|count| count.set(0));
        COUNT_ALLOCATIONS.with(|enabled| enabled.set(true));
        frame.encode_into(&mut encoded).unwrap();
        COUNT_ALLOCATIONS.with(|enabled| enabled.set(false));
        assert_eq!(ALLOCATION_COUNT.with(Cell::get), 0);
        assert_eq!(&encoded[HEADER_LEN + 8..], &[0xa5; 4096]);
        encoded.zeroize();
    }
}
