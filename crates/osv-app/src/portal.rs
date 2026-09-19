#![allow(unsafe_code)]

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use gtk::{gio, glib, prelude::*};
use zeroize::Zeroize;

const BROKER_ARGUMENT: &str = "--portal-broker";
const MAX_PATH_BYTES: usize = 4096;
const STATUS_SELECTED: u8 = 0;
const STATUS_CANCELLED: u8 = 1;
const STATUS_FAILED: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    Folder,
    Image,
}

impl Purpose {
    fn argument(self) -> &'static str {
        match self {
            Self::Folder => "folder",
            Self::Image => "image",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "folder" => Some(Self::Folder),
            "image" => Some(Self::Image),
            _ => None,
        }
    }
}

pub struct Selection {
    file: gio::File,
    descriptor: std::fs::File,
}

impl Selection {
    pub fn file(&self) -> gio::File {
        self.file.clone()
    }

    pub fn into_parts(self) -> (gio::File, std::fs::File) {
        (self.file, self.descriptor)
    }
}

pub enum Outcome {
    Selected(Selection),
    Cancelled,
    Failed,
}

pub fn select(purpose: Purpose, complete: impl FnOnce(Outcome) + 'static) {
    let (parent, child_socket) = match UnixDatagram::pair() {
        Ok(pair) => pair,
        Err(_) => {
            complete(Outcome::Failed);
            return;
        }
    };
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(_) => {
            complete(Outcome::Failed);
            return;
        }
    };
    let spawned = Command::new(executable)
        .arg(BROKER_ARGUMENT)
        .arg("0")
        .arg(purpose.argument())
        .stdin(Stdio::from(OwnedFd::from(child_socket)))
        .spawn();
    let Ok(child) = spawned else {
        complete(Outcome::Failed);
        return;
    };

    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let outcome = receive_selection(&parent, purpose).unwrap_or(Outcome::Failed);
        reap(child);
        let _ = sender.send(outcome);
    });
    let mut complete = Some(complete);
    glib::timeout_add_local(Duration::from_millis(20), move || {
        match receiver.try_recv() {
            Ok(outcome) => {
                if let Some(complete) = complete.take() {
                    complete(outcome);
                }
                glib::ControlFlow::Break
            }
            Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                if let Some(complete) = complete.take() {
                    complete(Outcome::Failed);
                }
                glib::ControlFlow::Break
            }
        }
    });
}

fn reap(mut child: Child) {
    let _ = child.wait();
}

pub fn run_broker_from_arguments() -> Option<glib::ExitCode> {
    let mut arguments = std::env::args();
    let _ = arguments.next();
    if arguments.next().as_deref() != Some(BROKER_ARGUMENT) {
        return None;
    }
    let Some(descriptor) = arguments
        .next()
        .and_then(|value| value.parse::<RawFd>().ok())
    else {
        return Some(glib::ExitCode::FAILURE);
    };
    let Some(purpose) = arguments.next().as_deref().and_then(Purpose::parse) else {
        return Some(glib::ExitCode::FAILURE);
    };
    if arguments.next().is_some() || descriptor != 0 {
        return Some(glib::ExitCode::FAILURE);
    }
    Some(run_broker(descriptor, purpose))
}

fn run_broker(descriptor: RawFd, purpose: Purpose) -> glib::ExitCode {
    // SAFETY: this mode owns the single inherited descriptor named by the
    // parent and rejects stdio or negative descriptor numbers above.
    let socket = unsafe { UnixDatagram::from_raw_fd(descriptor) };
    if gtk::init().is_err() {
        let _ = send_status(&socket, STATUS_FAILED);
        return glib::ExitCode::FAILURE;
    }
    let dialog = gtk::FileDialog::builder()
        .title(match purpose {
            Purpose::Folder => "Choose a folder",
            Purpose::Image => "Choose an image to import",
        })
        .modal(true)
        .build();
    if purpose == Purpose::Image {
        let filter = gtk::FileFilter::new();
        filter.set_name(Some("Supported images"));
        for mime in ["image/png", "image/jpeg", "image/gif", "image/webp"] {
            filter.add_mime_type(mime);
        }
        let filters = gio::ListStore::new::<gtk::FileFilter>();
        filters.append(&filter);
        dialog.set_filters(Some(&filters));
    }
    let main_loop = glib::MainLoop::new(None, false);
    let loop_for_result = main_loop.clone();
    let finish = move |result: Result<gio::File, glib::Error>| {
        let status = match result {
            Ok(file) => send_selected(&socket, &file, purpose),
            Err(error) if portal_error_is_cancelled(&error) => {
                send_status(&socket, STATUS_CANCELLED)
            }
            Err(_) => send_status(&socket, STATUS_FAILED),
        };
        let _ = status;
        loop_for_result.quit();
    };
    match purpose {
        Purpose::Folder => {
            dialog.select_folder(None::<&gtk::Window>, gio::Cancellable::NONE, finish)
        }
        Purpose::Image => dialog.open(None::<&gtk::Window>, gio::Cancellable::NONE, finish),
    }
    main_loop.run();
    glib::ExitCode::SUCCESS
}

fn portal_error_is_cancelled(error: &glib::Error) -> bool {
    error.matches(gtk::DialogError::Dismissed)
        || error.matches(gtk::DialogError::Cancelled)
        || error.matches(gio::IOErrorEnum::Cancelled)
}

fn send_selected(socket: &UnixDatagram, file: &gio::File, purpose: Purpose) -> io::Result<()> {
    let path = file
        .path()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let descriptor = match purpose {
        Purpose::Folder => open_selected_folder(&path)?,
        Purpose::Image => super::ui::open_portal_file(&path)?,
    };
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    if bytes.is_empty() || bytes.len() > MAX_PATH_BYTES {
        bytes.zeroize();
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut message = Vec::with_capacity(5 + bytes.len());
    message.push(STATUS_SELECTED);
    message.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    message.extend_from_slice(&bytes);
    bytes.zeroize();
    let result = send_with_descriptor(socket.as_raw_fd(), &message, descriptor.as_raw_fd());
    message.zeroize();
    result
}

fn open_selected_folder(path: &std::path::Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn send_status(socket: &UnixDatagram, status: u8) -> io::Result<()> {
    socket.send(&[status]).map(|_| ())
}

fn receive_selection(socket: &UnixDatagram, purpose: Purpose) -> io::Result<Outcome> {
    let mut message = [0_u8; MAX_PATH_BYTES + 5];
    let (length, descriptor) = receive_with_descriptor(socket.as_raw_fd(), &mut message)?;
    let outcome = (|| match message.get(..length) {
        Some([STATUS_CANCELLED]) if descriptor.is_none() => Ok(Outcome::Cancelled),
        Some([STATUS_FAILED]) if descriptor.is_none() => Ok(Outcome::Failed),
        Some(bytes) if bytes.first() == Some(&STATUS_SELECTED) && bytes.len() >= 5 => {
            let path_len =
                u32::from_le_bytes(bytes[1..5].try_into().expect("fixed slice")) as usize;
            if path_len == 0 || path_len > MAX_PATH_BYTES || bytes.len() != path_len + 5 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let descriptor =
                descriptor.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            validate_descriptor(descriptor.as_raw_fd(), purpose)?;
            let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&bytes[5..]));
            if !path.is_absolute() {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let file = gio::File::for_path(path);
            let descriptor = std::fs::File::from(descriptor);
            Ok(Outcome::Selected(Selection { file, descriptor }))
        }
        _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
    })();
    message.zeroize();
    outcome
}

#[allow(unsafe_code)]
fn validate_descriptor(descriptor: RawFd, purpose: Purpose) -> io::Result<()> {
    let mut metadata: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(descriptor, &mut metadata) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let kind = metadata.st_mode & libc::S_IFMT;
    if matches!(
        (purpose, kind),
        (Purpose::Folder, libc::S_IFDIR) | (Purpose::Image, libc::S_IFREG)
    ) {
        Ok(())
    } else {
        Err(io::Error::from(io::ErrorKind::InvalidData))
    }
}

#[allow(unsafe_code)]
fn send_with_descriptor(socket: RawFd, bytes: &[u8], descriptor: RawFd) -> io::Result<()> {
    let mut control = [0_u8; unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize];
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut header: libc::msghdr = unsafe { mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = control.len();
    // SAFETY: control has CMSG_SPACE bytes and header points at live buffers.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&header);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as usize;
        cmsg.cast::<u8>()
            .add(libc::CMSG_LEN(0) as usize)
            .cast::<RawFd>()
            .write(descriptor);
        let sent = libc::sendmsg(socket, &header, libc::MSG_NOSIGNAL);
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != bytes.len() {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn receive_with_descriptor(
    socket: RawFd,
    bytes: &mut [u8],
) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut control = [0_u8; unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut header: libc::msghdr = unsafe { mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = control.len();
    let received = unsafe { libc::recvmsg(socket, &mut header, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&header) };
    let descriptor = if cmsg.is_null() {
        None
    } else if unsafe { (*cmsg).cmsg_level } == libc::SOL_SOCKET
        && unsafe { (*cmsg).cmsg_type } == libc::SCM_RIGHTS
        && unsafe { (*cmsg).cmsg_len }
            == unsafe { libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) } as usize
        && unsafe { libc::CMSG_NXTHDR(&header, cmsg) }.is_null()
    {
        let raw = unsafe {
            cmsg.cast::<u8>()
                .add(libc::CMSG_LEN(0) as usize)
                .cast::<RawFd>()
                .read()
        };
        Some(unsafe { OwnedFd::from_raw_fd(raw) })
    } else {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    };
    Ok((received as usize, descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_file_requires_bounded_absolute_path_and_matching_descriptor_type() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        let file = std::fs::File::open("Cargo.toml").unwrap();
        let path = std::env::current_dir().unwrap().join("Cargo.toml");
        let bytes = path.as_os_str().as_bytes();
        let mut message = Vec::with_capacity(bytes.len() + 5);
        message.push(STATUS_SELECTED);
        message.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        message.extend_from_slice(bytes);
        send_with_descriptor(sender.as_raw_fd(), &message, file.as_raw_fd()).unwrap();
        assert!(matches!(
            receive_selection(&receiver, Purpose::Image).unwrap(),
            Outcome::Selected(_)
        ));

        let (sender, receiver) = UnixDatagram::pair().unwrap();
        send_with_descriptor(sender.as_raw_fd(), &message, file.as_raw_fd()).unwrap();
        assert!(receive_selection(&receiver, Purpose::Folder).is_err());
    }

    #[test]
    fn cancellation_has_no_descriptor_and_selected_requires_one() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        sender.send(&[STATUS_CANCELLED]).unwrap();
        assert!(matches!(
            receive_selection(&receiver, Purpose::Folder).unwrap(),
            Outcome::Cancelled
        ));

        let (sender, receiver) = UnixDatagram::pair().unwrap();
        sender.send(&[STATUS_SELECTED, 1, 0, 0, 0, b'/']).unwrap();
        assert!(receive_selection(&receiver, Purpose::Folder).is_err());
    }
}
