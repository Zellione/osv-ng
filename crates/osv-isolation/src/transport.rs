use osv_worker_protocol::{Frame, HEADER_LEN, MAX_PAYLOAD_LEN, ProtocolError};
use std::{
    error::Error,
    fmt,
    io::{self, IoSlice, IoSliceMut},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::net::UnixStream,
    time::Instant,
};
use zeroize::Zeroize;

#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    Protocol(ProtocolError),
    MissingDescriptor,
    ExtraDescriptor,
    InvalidDescriptor,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "worker transport I/O failed",
            Self::Protocol(_) => "worker transport protocol failed",
            Self::MissingDescriptor => "worker transport descriptor is missing",
            Self::ExtraDescriptor => "worker transport included extra descriptors",
            Self::InvalidDescriptor => "worker transport descriptor has an invalid type",
        })
    }
}

impl Error for TransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for TransportError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<ProtocolError> for TransportError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

pub struct PlaintextBuffer(osv_crypto::SecretBytes);

impl PlaintextBuffer {
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, TransportError> {
        if bytes.len() > osv_worker_protocol::MAX_DATA_LEN {
            bytes.as_mut_slice().zeroize();
            return Err(ProtocolError::Oversized.into());
        }
        osv_crypto::SecretBytes::take(bytes.as_mut_slice())
            .map(Self)
            .map_err(TransportError::Io)
    }
    pub fn as_slice(&self) -> &[u8] {
        self.0.expose()
    }
    pub fn lock_status(&self) -> osv_crypto::LockStatus {
        self.0.lock_status()
    }
}

pub struct FramedChannel {
    stream: UnixStream,
    deadline: Option<Instant>,
}

impl FramedChannel {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            deadline: None,
        }
    }
    pub fn stream(&self) -> &UnixStream {
        &self.stream
    }

    pub fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.deadline = deadline;
    }

    pub fn send(&mut self, frame: &Frame) -> Result<(), TransportError> {
        let mut encoded = osv_crypto::SecretBytes::zeroed(frame.encoded_len()?)?;
        frame.encode_into(encoded.expose_mut())?;
        self.write_all(encoded.expose()).map_err(Into::into)
    }

    pub(crate) fn send_nonblocking(&mut self, frame: &Frame) -> Result<(), TransportError> {
        let mut encoded = osv_crypto::SecretBytes::zeroed(frame.encoded_len()?)?;
        frame.encode_into(encoded.expose_mut())?;
        let written = send_bytes_nonblocking(self.stream.as_raw_fd(), encoded.expose())?;
        if written == encoded.len() {
            Ok(())
        } else {
            Err(io::Error::from(io::ErrorKind::WouldBlock).into())
        }
    }

    pub fn receive(&mut self) -> Result<Frame, TransportError> {
        let mut encoded = vec![0_u8; HEADER_LEN];
        self.read_exact(&mut encoded)?;
        let length = u32::from_le_bytes(encoded[12..16].try_into().expect("fixed slice")) as usize;
        if length > MAX_PAYLOAD_LEN {
            encoded.zeroize();
            return Err(ProtocolError::Oversized.into());
        }
        encoded.resize(HEADER_LEN + length, 0);
        if let Err(error) = self.read_exact(&mut encoded[HEADER_LEN..]) {
            encoded.zeroize();
            return Err(error.into());
        }
        let decoded = Frame::decode(&encoded);
        encoded.zeroize();
        decoded.map_err(Into::into)
    }

    fn read_exact(&mut self, mut bytes: &mut [u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            match read_bytes(self.stream.as_raw_fd(), bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(count) => bytes = &mut bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLIN)?
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            match send_bytes(self.stream.as_raw_fd(), bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLOUT)?
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn wait(&self, events: i16) -> io::Result<()> {
        let mut descriptor = libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events,
            revents: 0,
        };
        loop {
            let timeout = match self.deadline {
                None => -1,
                Some(deadline) => {
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
                    i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX)
                }
            };
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if result > 0 {
                return Ok(());
            }
            if result == 0 {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[allow(unsafe_code)]
fn read_bytes(descriptor: RawFd, bytes: &mut [u8]) -> io::Result<usize> {
    let result = unsafe { libc::read(descriptor, bytes.as_mut_ptr().cast(), bytes.len()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

#[allow(unsafe_code)]
fn send_bytes_nonblocking(descriptor: RawFd, bytes: &[u8]) -> io::Result<usize> {
    let result = unsafe {
        libc::send(
            descriptor,
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

#[allow(unsafe_code)]
fn send_bytes(descriptor: RawFd, bytes: &[u8]) -> io::Result<usize> {
    let iov = [IoSlice::new(bytes)];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = iov.as_ptr().cast_mut().cast();
    message.msg_iovlen = 1;
    let result = unsafe { libc::sendmsg(descriptor, &message, libc::MSG_NOSIGNAL) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

/// Sends exactly one already-open object-scoped descriptor with a fixed tag.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn send_descriptor(socket: &UnixStream, descriptor: RawFd) -> Result<(), TransportError> {
    let payload = [0x4f_u8];
    let iov = [IoSlice::new(&payload)];
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut control = [0_usize; 4];
    debug_assert!(space <= std::mem::size_of_val(&control));
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = iov.as_ptr().cast_mut().cast();
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
        if libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) != 1 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

/// Receives one descriptor, rejects truncation/multiplicity, and only accepts
/// regular files, pipes, or Unix sockets (never directories).
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn receive_descriptor(socket: &UnixStream) -> Result<OwnedFd, TransportError> {
    let mut payload = [0_u8];
    let mut iov = [IoSliceMut::new(&mut payload)];
    let space = unsafe { libc::CMSG_SPACE((2 * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut control = [0_usize; 4];
    debug_assert!(space <= std::mem::size_of_val(&control));
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = iov.as_mut_ptr().cast();
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space;
    let received =
        unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received != 1 {
        return Err(if received < 0 {
            io::Error::last_os_error().into()
        } else {
            TransportError::MissingDescriptor
        });
    }
    let mut descriptors = Vec::with_capacity(2);
    let mut unexpected_control = false;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        if unsafe {
            (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS
        } {
            let base = unsafe { libc::CMSG_LEN(0) as usize };
            let length = unsafe { (*header).cmsg_len };
            if length < base || (length - base) % std::mem::size_of::<RawFd>() != 0 {
                unexpected_control = true;
            } else {
                let count = (length - base) / std::mem::size_of::<RawFd>();
                for index in 0..count {
                    descriptors.push(unsafe {
                        std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>().add(index))
                    });
                }
            }
        } else {
            unexpected_control = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    let invalid = payload != [0x4f]
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || unexpected_control;
    if invalid || descriptors.len() != 1 {
        let error = if invalid {
            TransportError::InvalidDescriptor
        } else if descriptors.is_empty() {
            TransportError::MissingDescriptor
        } else {
            TransportError::ExtraDescriptor
        };
        for descriptor in descriptors {
            unsafe { libc::close(descriptor) };
        }
        return Err(error);
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut status) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let kind = status.st_mode & libc::S_IFMT;
    if !matches!(kind, libc::S_IFREG | libc::S_IFIFO | libc::S_IFSOCK) {
        return Err(TransportError::InvalidDescriptor);
    }
    Ok(descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[allow(unsafe_code)]
    fn send_two_descriptors(socket: &UnixStream, descriptors: [RawFd; 2]) {
        let payload = [0x4f_u8];
        let iov = [IoSlice::new(&payload)];
        let space =
            unsafe { libc::CMSG_SPACE(std::mem::size_of_val(&descriptors) as u32) } as usize;
        let mut control = [0_usize; 4];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = iov.as_ptr().cast_mut().cast();
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of_val(&descriptors) as u32) as usize;
            std::ptr::copy_nonoverlapping(
                descriptors.as_ptr(),
                libc::CMSG_DATA(header).cast::<RawFd>(),
                2,
            );
            assert_eq!(
                libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                1
            );
        }
    }

    #[test]
    fn bounded_plaintext_and_descriptor_contract() {
        assert!(matches!(
            PlaintextBuffer::new(vec![0; osv_worker_protocol::MAX_DATA_LEN + 1]),
            Err(TransportError::Protocol(ProtocolError::Oversized))
        ));

        let (left, right) = UnixStream::pair().unwrap();
        let (content, _) = UnixStream::pair().unwrap();
        send_descriptor(&left, content.as_raw_fd()).unwrap();
        let received = receive_descriptor(&right).unwrap();
        assert_ne!(received.as_fd().as_raw_fd(), content.as_raw_fd());

        let (left, right) = UnixStream::pair().unwrap();
        let (first, second) = UnixStream::pair().unwrap();
        send_two_descriptors(&left, [first.as_raw_fd(), second.as_raw_fd()]);
        assert!(matches!(
            receive_descriptor(&right),
            Err(TransportError::ExtraDescriptor)
        ));

        let (left, right) = UnixStream::pair().unwrap();
        let directory = std::fs::File::open(".").unwrap();
        send_descriptor(&left, directory.as_raw_fd()).unwrap();
        assert!(matches!(
            receive_descriptor(&right),
            Err(TransportError::InvalidDescriptor)
        ));
    }
}
