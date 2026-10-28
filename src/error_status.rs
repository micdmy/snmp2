//! SNMP Response-PDU `error-status` and related error payload.
//!
//! Values are defined in [RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html) §3.

use std::fmt;

/// SNMP Response-PDU `error-status` ([RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html) §3).
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ErrorStatus {
    /// `noError(0)`
    NoError,
    /// `tooBig(1)` — response would exceed maximum message size.
    TooBig,
    /// `noSuchName(2)` — for proxy compatibility with SNMPv1.
    NoSuchName,
    /// `badValue(3)` — for proxy compatibility with SNMPv1.
    BadValue,
    /// `readOnly(4)` — for proxy compatibility with SNMPv1.
    ReadOnly,
    /// `genErr(5)`
    GenErr,
    /// `noAccess(6)`
    NoAccess,
    /// `wrongType(7)`
    WrongType,
    /// `wrongLength(8)`
    WrongLength,
    /// `wrongEncoding(9)`
    WrongEncoding,
    /// `wrongValue(10)`
    WrongValue,
    /// `noCreation(11)`
    NoCreation,
    /// `inconsistentValue(12)`
    InconsistentValue,
    /// `resourceUnavailable(13)`
    ResourceUnavailable,
    /// `commitFailed(14)`
    CommitFailed,
    /// `undoFailed(15)`
    UndoFailed,
    /// `authorizationError(16)`
    AuthorizationError,
    /// `notWritable(17)`
    NotWritable,
    /// `inconsistentName(18)`
    InconsistentName,
    /// Value not defined in RFC 3416.
    Unknown(u32),
}

impl From<u32> for ErrorStatus {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::TooBig,
            2 => Self::NoSuchName,
            3 => Self::BadValue,
            4 => Self::ReadOnly,
            5 => Self::GenErr,
            6 => Self::NoAccess,
            7 => Self::WrongType,
            8 => Self::WrongLength,
            9 => Self::WrongEncoding,
            10 => Self::WrongValue,
            11 => Self::NoCreation,
            12 => Self::InconsistentValue,
            13 => Self::ResourceUnavailable,
            14 => Self::CommitFailed,
            15 => Self::UndoFailed,
            16 => Self::AuthorizationError,
            17 => Self::NotWritable,
            18 => Self::InconsistentName,
            other => Self::Unknown(other),
        }
    }
}

impl From<ErrorStatus> for u32 {
    fn from(value: ErrorStatus) -> Self {
        match value {
            ErrorStatus::NoError => 0,
            ErrorStatus::TooBig => 1,
            ErrorStatus::NoSuchName => 2,
            ErrorStatus::BadValue => 3,
            ErrorStatus::ReadOnly => 4,
            ErrorStatus::GenErr => 5,
            ErrorStatus::NoAccess => 6,
            ErrorStatus::WrongType => 7,
            ErrorStatus::WrongLength => 8,
            ErrorStatus::WrongEncoding => 9,
            ErrorStatus::WrongValue => 10,
            ErrorStatus::NoCreation => 11,
            ErrorStatus::InconsistentValue => 12,
            ErrorStatus::ResourceUnavailable => 13,
            ErrorStatus::CommitFailed => 14,
            ErrorStatus::UndoFailed => 15,
            ErrorStatus::AuthorizationError => 16,
            ErrorStatus::NotWritable => 17,
            ErrorStatus::InconsistentName => 18,
            ErrorStatus::Unknown(v) => v,
        }
    }
}

impl fmt::Display for ErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "noError"),
            Self::TooBig => write!(f, "tooBig"),
            Self::NoSuchName => write!(f, "noSuchName"),
            Self::BadValue => write!(f, "badValue"),
            Self::ReadOnly => write!(f, "readOnly"),
            Self::GenErr => write!(f, "genErr"),
            Self::NoAccess => write!(f, "noAccess"),
            Self::WrongType => write!(f, "wrongType"),
            Self::WrongLength => write!(f, "wrongLength"),
            Self::WrongEncoding => write!(f, "wrongEncoding"),
            Self::WrongValue => write!(f, "wrongValue"),
            Self::NoCreation => write!(f, "noCreation"),
            Self::InconsistentValue => write!(f, "inconsistentValue"),
            Self::ResourceUnavailable => write!(f, "resourceUnavailable"),
            Self::CommitFailed => write!(f, "commitFailed"),
            Self::UndoFailed => write!(f, "undoFailed"),
            Self::AuthorizationError => write!(f, "authorizationError"),
            Self::NotWritable => write!(f, "notWritable"),
            Self::InconsistentName => write!(f, "inconsistentName"),
            Self::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

/// Non-success SNMP Response-PDU status reported to the caller.
///
/// Built from Response-PDU `error-status` and `error-index`
/// ([RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html) §4.2).
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ResponseStatus {
    /// PDU `error-status`.
    pub status: ErrorStatus,
    index: u32,
}

impl ResponseStatus {
    /// Create from wire `error-status` and `error-index`.
    pub fn new(status: ErrorStatus, index: u32) -> Self {
        Self { status, index }
    }

    /// 1-based index of the request varbind that caused the error, if any.
    ///
    /// Returns `None` when `error-index` is 0 (e.g. `tooBig`).
    pub fn related_oid_index(&self) -> Option<u32> {
        if self.index == 0 {
            None
        } else {
            Some(self.index)
        }
    }
}

impl fmt::Display for ResponseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SNMP error-status {} ({}), error-index {}",
            self.status,
            u32::from(self.status),
            self.index
        )
    }
}
