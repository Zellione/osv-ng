use std::{error::Error, fmt, io};

/// Catalog failures deliberately omit SQL values, keys, and paths.
#[derive(Debug)]
pub enum CatalogError {
    AlreadyExists,
    InvalidInput(&'static str),
    UnknownSchema(u32),
    MigrationInterrupted,
    IntegrityFailed,
    NotFound,
    Conflict,
    Sql(rusqlite::Error),
    Io(io::Error),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => formatter.write_str("catalog already exists"),
            Self::InvalidInput(kind) => write!(formatter, "invalid catalog {kind}"),
            Self::UnknownSchema(version) => {
                write!(formatter, "unsupported catalog schema {version}")
            }
            Self::MigrationInterrupted => formatter.write_str("catalog migration interrupted"),
            Self::IntegrityFailed => formatter.write_str("catalog integrity check failed"),
            Self::NotFound => formatter.write_str("catalog record not found"),
            Self::Conflict => formatter.write_str("catalog constraint conflict"),
            Self::Sql(_) => formatter.write_str("encrypted catalog operation failed"),
            Self::Io(_) => formatter.write_str("catalog filesystem operation failed"),
        }
    }
}

impl Error for CatalogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sql(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for CatalogError {
    fn from(error: rusqlite::Error) -> Self {
        if matches!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::ConstraintViolation)
        ) {
            Self::Conflict
        } else {
            Self::Sql(error)
        }
    }
}

impl From<io::Error> for CatalogError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, CatalogError>;
