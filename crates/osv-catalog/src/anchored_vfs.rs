#![allow(unsafe_code)]

use std::{
    ffi::{CStr, CString},
    fs::File,
    mem::size_of,
    os::fd::AsRawFd,
    os::unix::ffi::OsStrExt,
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};

use rusqlite::ffi;

use crate::CatalogError;

static NEXT_VFS_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_RETIRED_ID: AtomicU64 = AtomicU64::new(1);

struct Context {
    directory: File,
    logical_database: CString,
}

#[repr(C)]
struct AnchoredFile {
    base: ffi::sqlite3_file,
    descriptor: libc::c_int,
    persistent_wal: libc::c_int,
}

pub(crate) struct AnchoredVfs {
    vfs: Box<ffi::sqlite3_vfs>,
    context: Box<Context>,
    name: CString,
    database_name: CString,
}

impl AnchoredVfs {
    pub(crate) fn register(directory: File) -> Result<Self, CatalogError> {
        let name = CString::new(format!(
            "osv-anchored-{}-{}",
            std::process::id(),
            NEXT_VFS_ID.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("generated VFS name has no NUL");
        let database_name = CString::new(format!("/osv/{}/catalog.db", name.to_string_lossy()))
            .expect("generated database name has no NUL");
        // SAFETY: SQLite owns the returned static built-in VFS for process life.
        let original = unsafe { ffi::sqlite3_vfs_find(c"unix".as_ptr()) };
        if original.is_null() {
            return Err(CatalogError::IntegrityFailed);
        }
        let mut context = Box::new(Context {
            directory,
            logical_database: database_name.clone(),
        });
        // Clone only platform services such as randomness and time. All
        // filename-bearing callbacks and file I/O are replaced below.
        // SAFETY: the built-in VFS is live and the structure is Copy.
        let mut vfs = Box::new(unsafe { *original });
        vfs.pNext = ptr::null_mut();
        vfs.zName = name.as_ptr();
        vfs.pAppData = ptr::from_mut(context.as_mut()).cast();
        vfs.szOsFile = i32::try_from(size_of::<AnchoredFile>())
            .expect("anchored SQLite file structure fits c_int");
        vfs.xOpen = Some(x_open);
        vfs.xDelete = Some(x_delete);
        vfs.xAccess = Some(x_access);
        vfs.xFullPathname = Some(x_full_pathname);
        // SAFETY: all pointers remain stable until the connection is closed.
        if unsafe { ffi::sqlite3_vfs_register(vfs.as_mut(), 0) } != ffi::SQLITE_OK {
            return Err(CatalogError::IntegrityFailed);
        }
        Ok(Self {
            vfs,
            context,
            name,
            database_name,
        })
    }

    pub(crate) fn name(&self) -> &str {
        self.name.to_str().expect("generated VFS name is UTF-8")
    }

    pub(crate) fn database_name(&self) -> &std::path::Path {
        std::path::Path::new(std::ffi::OsStr::from_bytes(self.database_name.as_bytes()))
    }
}

impl Drop for AnchoredVfs {
    fn drop(&mut self) {
        // SAFETY: Catalog declares its connection before this VFS, so field
        // destruction closes every SQLite file before unregistering the VFS.
        unsafe { ffi::sqlite3_vfs_unregister(self.vfs.as_mut()) };
        let _ = &self.context;
    }
}

fn context(vfs: *mut ffi::sqlite3_vfs) -> &'static Context {
    // SAFETY: registered callbacks receive the VFS whose pAppData points to
    // the stable boxed Context for longer than any connection or file.
    unsafe { &*((*vfs).pAppData.cast::<Context>()) }
}

fn member_name(context: &Context, path: *const libc::c_char) -> Option<&'static CStr> {
    if path.is_null() {
        return None;
    }
    // SAFETY: SQLite supplies a NUL-terminated filename to VFS callbacks.
    let path = unsafe { CStr::from_ptr(path) }.to_bytes();
    let database = context.logical_database.as_bytes();
    if path == database {
        return Some(c"catalog.db");
    }
    match path.strip_prefix(database)? {
        b"-wal" => Some(c"catalog.db-wal"),
        b"-shm" => Some(c"catalog.db-shm"),
        b"-journal" => Some(c"catalog.db-journal"),
        _ => None,
    }
}

unsafe extern "C" fn x_open(
    vfs: *mut ffi::sqlite3_vfs,
    path: ffi::sqlite3_filename,
    output: *mut ffi::sqlite3_file,
    flags: libc::c_int,
    output_flags: *mut libc::c_int,
) -> libc::c_int {
    let context = context(vfs);
    let Some(member) = member_name(context, path) else {
        // No temporary, attached, or externally named file may inherit this
        // VFS's vault authority. temp_store is MEMORY and ATTACH is disabled.
        return ffi::SQLITE_CANTOPEN;
    };
    if member == c"catalog.db-shm" || flags & ffi::SQLITE_OPEN_SUPER_JOURNAL != 0 {
        // Exclusive writers use an in-process WAL index. Super-journal names
        // may originate in an unauthenticated rollback-journal trailer.
        return ffi::SQLITE_CANTOPEN;
    }
    let access = if flags & ffi::SQLITE_OPEN_READONLY != 0 {
        libc::O_RDONLY
    } else {
        libc::O_RDWR
    };
    let create = i32::from(flags & ffi::SQLITE_OPEN_CREATE != 0) * libc::O_CREAT;
    let exclusive = i32::from(flags & ffi::SQLITE_OPEN_EXCLUSIVE != 0) * libc::O_EXCL;
    // SAFETY: the held directory descriptor and fixed member pointer are valid.
    let descriptor = unsafe {
        libc::openat(
            context.directory.as_raw_fd(),
            member.as_ptr(),
            access | create | exclusive | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return ffi::SQLITE_CANTOPEN;
    }
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: descriptor is live and metadata points to writable storage.
    if unsafe { libc::fstat(descriptor, &mut metadata) } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_nlink != 1
    {
        unsafe { libc::close(descriptor) };
        return ffi::SQLITE_CANTOPEN;
    }
    if create != 0 && context.directory.sync_all().is_err() {
        // Sync even when the entry already existed. This conservatively
        // preserves SQLite's new journal/WAL directory-durability contract
        // without reopening a pathname to determine which descriptor it used.
        unsafe { libc::close(descriptor) };
        return ffi::SQLITE_IOERR_DIR_FSYNC;
    }
    if !output_flags.is_null() {
        unsafe { *output_flags = flags };
    }
    let file = AnchoredFile {
        base: ffi::sqlite3_file {
            pMethods: &IO_METHODS,
        },
        descriptor,
        persistent_wal: 0,
    };
    // SAFETY: SQLite allocated and aligned vfs.szOsFile bytes for output.
    unsafe { output.cast::<AnchoredFile>().write(file) };
    ffi::SQLITE_OK
}

fn anchored_file(file: *mut ffi::sqlite3_file) -> &'static mut AnchoredFile {
    // SAFETY: pointers using IO_METHODS were initialized as AnchoredFile and
    // remain exclusive to the synchronous callback.
    unsafe { &mut *file.cast::<AnchoredFile>() }
}

unsafe extern "C" fn io_close(file: *mut ffi::sqlite3_file) -> libc::c_int {
    let file = anchored_file(file);
    let result = unsafe { libc::close(file.descriptor) };
    file.descriptor = -1;
    file.base.pMethods = ptr::null();
    if result == 0 {
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_IOERR_CLOSE
    }
}

unsafe extern "C" fn io_read(
    file: *mut ffi::sqlite3_file,
    output: *mut libc::c_void,
    amount: libc::c_int,
    offset: ffi::sqlite3_int64,
) -> libc::c_int {
    let Ok(amount) = usize::try_from(amount) else {
        return ffi::SQLITE_IOERR_READ;
    };
    let mut offset = offset;
    let file = anchored_file(file);
    let mut completed = 0;
    while completed < amount {
        let result = unsafe {
            libc::pread(
                file.descriptor,
                output.cast::<u8>().add(completed).cast(),
                amount - completed,
                offset,
            )
        };
        if result == 0 {
            unsafe { ptr::write_bytes(output.cast::<u8>().add(completed), 0, amount - completed) };
            return ffi::SQLITE_IOERR_SHORT_READ;
        }
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return ffi::SQLITE_IOERR_READ;
        }
        completed += usize::try_from(result).expect("positive pread result fits usize");
        offset += i64::try_from(result).expect("positive pread result fits i64");
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_write(
    file: *mut ffi::sqlite3_file,
    input: *const libc::c_void,
    amount: libc::c_int,
    offset: ffi::sqlite3_int64,
) -> libc::c_int {
    let Ok(amount) = usize::try_from(amount) else {
        return ffi::SQLITE_IOERR_WRITE;
    };
    let mut offset = offset;
    let file = anchored_file(file);
    let mut completed = 0;
    while completed < amount {
        let result = unsafe {
            libc::pwrite(
                file.descriptor,
                input.cast::<u8>().add(completed).cast(),
                amount - completed,
                offset,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return if error.raw_os_error() == Some(libc::ENOSPC) {
                ffi::SQLITE_FULL
            } else {
                ffi::SQLITE_IOERR_WRITE
            };
        }
        if result == 0 {
            return ffi::SQLITE_IOERR_WRITE;
        }
        completed += usize::try_from(result).expect("positive pwrite result fits usize");
        offset += i64::try_from(result).expect("positive pwrite result fits i64");
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_truncate(
    file: *mut ffi::sqlite3_file,
    size: ffi::sqlite3_int64,
) -> libc::c_int {
    if size < 0 {
        return ffi::SQLITE_IOERR_TRUNCATE;
    }
    if unsafe { libc::ftruncate(anchored_file(file).descriptor, size) } == 0 {
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_IOERR_TRUNCATE
    }
}

unsafe extern "C" fn io_sync(file: *mut ffi::sqlite3_file, _flags: libc::c_int) -> libc::c_int {
    if unsafe { libc::fsync(anchored_file(file).descriptor) } == 0 {
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_IOERR_FSYNC
    }
}

unsafe extern "C" fn io_file_size(
    file: *mut ffi::sqlite3_file,
    output: *mut ffi::sqlite3_int64,
) -> libc::c_int {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(anchored_file(file).descriptor, &mut metadata) } != 0 {
        return ffi::SQLITE_IOERR_FSTAT;
    }
    unsafe { *output = metadata.st_size };
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_lock(_file: *mut ffi::sqlite3_file, _lock: libc::c_int) -> libc::c_int {
    // VaultService's lifetime flock is the Phase 6 locking authority.
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_unlock(_file: *mut ffi::sqlite3_file, _lock: libc::c_int) -> libc::c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_check_reserved_lock(
    _file: *mut ffi::sqlite3_file,
    output: *mut libc::c_int,
) -> libc::c_int {
    unsafe { *output = 0 };
    ffi::SQLITE_OK
}

unsafe extern "C" fn io_file_control(
    file: *mut ffi::sqlite3_file,
    operation: libc::c_int,
    argument: *mut libc::c_void,
) -> libc::c_int {
    if operation == ffi::SQLITE_FCNTL_PERSIST_WAL {
        if argument.is_null() {
            return ffi::SQLITE_MISUSE;
        }
        let file = anchored_file(file);
        let requested = unsafe { *argument.cast::<libc::c_int>() };
        if requested >= 0 {
            file.persistent_wal = i32::from(requested != 0);
        }
        unsafe { *argument.cast::<libc::c_int>() = file.persistent_wal };
        return ffi::SQLITE_OK;
    }
    if operation == ffi::SQLITE_FCNTL_HAS_MOVED {
        if argument.is_null() {
            return ffi::SQLITE_MISUSE;
        }
        unsafe { *argument.cast::<libc::c_int>() = 0 };
        return ffi::SQLITE_OK;
    }
    ffi::SQLITE_NOTFOUND
}

unsafe extern "C" fn io_sector_size(_file: *mut ffi::sqlite3_file) -> libc::c_int {
    4096
}

unsafe extern "C" fn io_device_characteristics(_file: *mut ffi::sqlite3_file) -> libc::c_int {
    0
}

static IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(io_close),
    xRead: Some(io_read),
    xWrite: Some(io_write),
    xTruncate: Some(io_truncate),
    xSync: Some(io_sync),
    xFileSize: Some(io_file_size),
    xLock: Some(io_lock),
    xUnlock: Some(io_unlock),
    xCheckReservedLock: Some(io_check_reserved_lock),
    xFileControl: Some(io_file_control),
    xSectorSize: Some(io_sector_size),
    xDeviceCharacteristics: Some(io_device_characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

unsafe extern "C" fn x_delete(
    vfs: *mut ffi::sqlite3_vfs,
    path: *const libc::c_char,
    sync_directory: libc::c_int,
) -> libc::c_int {
    let context = context(vfs);
    let Some(member) = member_name(context, path) else {
        return ffi::SQLITE_IOERR_DELETE;
    };
    let retired = CString::new(format!(
        ".osv-sqlite-retired-{}-{}",
        std::process::id(),
        NEXT_RETIRED_ID.fetch_add(1, Ordering::Relaxed)
    ))
    .expect("generated retired name has no NUL");
    let result = unsafe {
        libc::renameat2(
            context.directory.as_raw_fd(),
            member.as_ptr(),
            context.directory.as_raw_fd(),
            retired.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        if sync_directory != 0 && context.directory.sync_all().is_err() {
            return ffi::SQLITE_IOERR_DIR_FSYNC;
        }
        ffi::SQLITE_OK
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_IOERR_DELETE
    }
}

unsafe extern "C" fn x_access(
    vfs: *mut ffi::sqlite3_vfs,
    path: *const libc::c_char,
    _flags: libc::c_int,
    result: *mut libc::c_int,
) -> libc::c_int {
    let context = context(vfs);
    let Some(member) = member_name(context, path) else {
        unsafe { *result = 0 };
        return ffi::SQLITE_OK;
    };
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    let status = unsafe {
        libc::fstatat(
            context.directory.as_raw_fd(),
            member.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    unsafe {
        *result = i32::from(
            status == 0
                && metadata.st_mode & libc::S_IFMT == libc::S_IFREG
                && metadata.st_nlink == 1,
        );
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn x_full_pathname(
    _vfs: *mut ffi::sqlite3_vfs,
    path: *const libc::c_char,
    output_len: libc::c_int,
    output: *mut libc::c_char,
) -> libc::c_int {
    if path.is_null() || output_len <= 0 {
        return ffi::SQLITE_CANTOPEN;
    }
    let input = unsafe { CStr::from_ptr(path) }.to_bytes_with_nul();
    let Ok(capacity) = usize::try_from(output_len) else {
        return ffi::SQLITE_CANTOPEN;
    };
    if input.len() > capacity {
        return ffi::SQLITE_CANTOPEN;
    }
    unsafe { ptr::copy_nonoverlapping(input.as_ptr().cast(), output, input.len()) };
    ffi::SQLITE_OK
}

#[cfg(test)]
mod tests {
    use std::{ffi::CString, fs, mem::MaybeUninit, path::Path};

    use osv_test_support::TempVault;
    use rusqlite::ffi;

    use super::{
        AnchoredFile, AnchoredVfs, io_close, io_sync, io_write, x_access, x_delete, x_open,
    };

    #[test]
    fn opened_file_io_stays_on_validated_inode_after_name_replacement() {
        let directory = TempVault::create_in(Path::new("/tmp")).unwrap();
        let database = directory.path().join("catalog.db");
        fs::write(&database, b"original").unwrap();
        let mut vfs = AnchoredVfs::register(fs::File::open(directory.path()).unwrap()).unwrap();
        let mut output = MaybeUninit::<AnchoredFile>::uninit();
        let result = unsafe {
            x_open(
                vfs.vfs.as_mut(),
                vfs.database_name.as_ptr(),
                output.as_mut_ptr().cast(),
                ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_READWRITE,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, ffi::SQLITE_OK);
        let moved = directory.path().join("moved.db");
        fs::rename(&database, &moved).unwrap();
        fs::write(&database, b"replacement").unwrap();
        let marker = b"pinned";
        let file = output.as_mut_ptr().cast::<ffi::sqlite3_file>();
        assert_eq!(
            unsafe { io_write(file, marker.as_ptr().cast(), marker.len() as i32, 0) },
            ffi::SQLITE_OK
        );
        assert_eq!(unsafe { io_sync(file, 0) }, ffi::SQLITE_OK);
        assert_eq!(unsafe { io_close(file) }, ffi::SQLITE_OK);
        assert!(fs::read(moved).unwrap().starts_with(marker));
        assert_eq!(fs::read(database).unwrap(), b"replacement");
    }

    #[test]
    fn unknown_recovery_names_have_no_filesystem_authority() {
        let directory = TempVault::create_in(Path::new("/tmp")).unwrap();
        fs::write(directory.path().join("catalog.db"), b"catalog").unwrap();
        let victim = directory.path().join("outside-victim");
        fs::write(&victim, b"survives").unwrap();
        let outside = CString::new(victim.as_os_str().as_encoded_bytes()).unwrap();
        let mut vfs = AnchoredVfs::register(fs::File::open(directory.path()).unwrap()).unwrap();
        let mut accessible = 1;
        assert_eq!(
            unsafe { x_access(vfs.vfs.as_mut(), outside.as_ptr(), 0, &mut accessible) },
            ffi::SQLITE_OK
        );
        assert_eq!(accessible, 0);
        assert_eq!(
            unsafe { x_delete(vfs.vfs.as_mut(), outside.as_ptr(), 1) },
            ffi::SQLITE_IOERR_DELETE
        );
        assert_eq!(fs::read(victim).unwrap(), b"survives");
    }
}
