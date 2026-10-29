#![ doc = include_str!( concat!( env!( "CARGO_MANIFEST_DIR" ), "/", "README.md" ) ) ]
#![allow(unknown_lints, clippy::doc_markdown)]

#[cfg(all(
    feature = "v3",
    not(feature = "crypto-openssl"),
    not(feature = "crypto-rust")
))]
compile_error!("feature \"v3\" requires one of \"crypto-openssl\" or \"crypto-rust\"");

use std::fmt;

pub mod asn1;
pub use asn1::AsnReader;
pub mod error_status;
#[cfg(feature = "mibs")]
pub mod mibs;
pub mod pdu;
pub mod snmp;
mod syncsession;
#[cfg(feature = "v3")]
pub mod v3;
#[cfg(feature = "crypto-openssl")]
pub use openssl;
pub use syncsession::SyncSession;
#[cfg(feature = "tokio")]
mod asyncsession;
#[cfg(feature = "tokio")]
pub use asyncsession::AsyncSession;

pub use error_status::{ErrorStatus, ResponseStatus};
pub use pdu::Pdu;

pub use asn1_rs::Oid;

#[cfg(target_pointer_width = "32")]
const USIZE_LEN: usize = 4;
#[cfg(target_pointer_width = "64")]
const USIZE_LEN: usize = 8;

/// SNMP protocol version.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(i64)]
pub enum Version {
    /// SNMPv1
    V1 = 0,
    /// SNMPv2c
    V2C = 1,
    /// SNMPv3
    V3 = 3,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Version::V1 => write!(f, "SNMPv1"),
            Version::V2C => write!(f, "SNMPv2c"),
            Version::V3 => write!(f, "SNMPv3"),
        }
    }
}

impl TryFrom<i64> for Version {
    type Error = Error;

    fn try_from(value: i64) -> Result<Version> {
        match value {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2C),
            3 => Ok(Version::V3),
            _ => Err(Error::UnsupportedVersion),
        }
    }
}

#[cfg(test)]
mod tests;

/// SNMP error type.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Error {
    /// ASN.1 parsing error.
    AsnParse,
    /// ASN.1 invalid length.
    AsnInvalidLen,
    /// ASN.1 wrong type.
    AsnWrongType,
    /// ASN.1 unsupported type.
    AsnUnsupportedType,
    /// ASN.1 unexpected end of file.
    AsnEof,
    /// ASN.1 integer overflow.
    AsnIntOverflow,

    /// Invalid SNMP version.
    UnsupportedVersion,
    /// Invalid request ID.
    RequestIdMismatch,
    /// Invalid SNMP community string.
    CommunityMismatch,
    /// Value out of range.
    ValueOutOfRange,
    /// Buffer overflow.
    BufferOverflow,

    /// Authentication failure
    #[cfg(feature = "v3")]
    AuthFailure(v3::AuthErrorKind),
    /// OpenSSL errors
    #[cfg(feature = "v3")]
    Crypto(String),
    /// Security context has been updated, repeat the request
    #[cfg(feature = "v3")]
    AuthUpdated,

    /// Socket send error.
    Send,
    /// Socket receive error.
    Receive,
    /// MIB errors
    Mib(String),
    /// Non-zero Response-PDU `error-status` ([RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html)).
    ResponseStatus(ResponseStatus),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AsnParse => write!(f, "ASN.1 parsing error"),
            Error::AsnInvalidLen => write!(f, "ASN.1 invalid length"),
            Error::AsnWrongType => write!(f, "ASN.1 wrong type"),
            Error::AsnUnsupportedType => write!(f, "ASN.1 unsupported type"),
            Error::AsnEof => write!(f, "ASN.1 unexpected end of file"),
            Error::AsnIntOverflow => write!(f, "ASN.1 integer overflow"),
            Error::UnsupportedVersion => write!(f, "Unsupported SNMP version"),
            Error::RequestIdMismatch => write!(f, "Request ID mismatch"),
            Error::CommunityMismatch => write!(f, "Community string mismatch"),
            Error::ValueOutOfRange => write!(f, "Value out of range"),
            Error::BufferOverflow => write!(f, "Buffer overflow"),
            #[cfg(feature = "v3")]
            Error::AuthFailure(err) => write!(f, "Authentication failure: {}", err),
            #[cfg(feature = "v3")]
            Error::Crypto(e) => write!(f, "Cryptographic engine error: {}", e),
            #[cfg(feature = "v3")]
            Error::AuthUpdated => {
                write!(f, "Security context has been updated, repeat the request")
            }
            Error::Send => write!(f, "Socket send error"),
            Error::Receive => write!(f, "Socket receive error"),
            Error::Mib(s) => write!(f, "MIB error: {}", s),
            Error::ResponseStatus(status) => write!(f, "{status}"),
        }
    }
}

#[cfg(feature = "crypto-openssl")]
impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Error {
        Error::Crypto(err.to_string())
    }
}

impl std::error::Error for Error {}

impl From<std::num::TryFromIntError> for Error {
    fn from(_: std::num::TryFromIntError) -> Error {
        Error::AsnIntOverflow
    }
}

type Result<T> = std::result::Result<T, Error>;

const BUFFER_SIZE: usize = 65_507;

/// Storage strategy for payload-bearing [`ValueBuf`] variants (octets, OIDs, nested ASN).
pub trait ValueStorage {
    type Octets: AsRef<[u8]> + Clone;
    type Oid: Clone + fmt::Display;
    type Nested: Clone + fmt::Debug;
}

/// Borrowed storage: session/receive-buffer lifetimes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Borrowed<'a>(core::marker::PhantomData<&'a ()>);

impl<'a> ValueStorage for Borrowed<'a> {
    type Octets = &'a [u8];
    type Oid = Oid<'a>;
    type Nested = AsnReader<'a>;
}

/// Owned storage: values outlive the session receive buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Owned;

impl ValueStorage for Owned {
    type Octets = Vec<u8>;
    type Oid = Oid<'static>;
    type Nested = Vec<u8>;
}

/// SNMP value parameterized by [`ValueStorage`]. Prefer the aliases [`Value`] / [`OwnedValue`].
#[derive(Clone)]
pub enum ValueBuf<S: ValueStorage> {
    Boolean(bool),
    Null,
    Integer(i64),
    OctetString(S::Octets),
    ObjectIdentifier(S::Oid),
    Sequence(S::Nested),
    Set(S::Nested),
    Constructed(u8, S::Nested),

    IpAddress([u8; 4]),
    Counter32(u32),
    Unsigned32(u32),
    Timeticks(u32),
    Opaque(S::Octets),
    Counter64(u64),

    EndOfMibView,
    NoSuchObject,
    NoSuchInstance,

    GetRequest(S::Nested),
    GetNextRequest(S::Nested),
    GetBulkRequest(S::Nested),
    Response(S::Nested),
    SetRequest(S::Nested),
    InformRequest(S::Nested),
    Trap(S::Nested),
    Report(S::Nested),
}

/// Value borrowed from a parse/session buffer.
pub type Value<'a> = ValueBuf<Borrowed<'a>>;
/// Value that owns its octets / nested ASN bytes / OID.
pub type OwnedValue = ValueBuf<Owned>;

/// Owned OID + value pair from a varbind list.
pub type OwnedVarbind = (Oid<'static>, OwnedValue);

impl OwnedValue {
    /// Borrow as a [`Value`] tied to this owned storage.
    pub fn as_value(&self) -> Value<'_> {
        use ValueBuf::*;
        match self {
            Self::Boolean(v) => Boolean(*v),
            Self::Null => Null,
            Self::Integer(n) => Integer(*n),
            Self::OctetString(s) => OctetString(s.as_slice()),
            Self::ObjectIdentifier(oid) => ObjectIdentifier(oid.clone()),
            Self::Sequence(b) => Sequence(AsnReader::from_bytes(b)),
            Self::Set(b) => Set(AsnReader::from_bytes(b)),
            Self::Constructed(ident, b) => Constructed(*ident, AsnReader::from_bytes(b)),
            Self::IpAddress(a) => IpAddress(*a),
            Self::Counter32(v) => Counter32(*v),
            Self::Unsigned32(v) => Unsigned32(*v),
            Self::Timeticks(v) => Timeticks(*v),
            Self::Opaque(b) => Opaque(b.as_slice()),
            Self::Counter64(v) => Counter64(*v),
            Self::EndOfMibView => EndOfMibView,
            Self::NoSuchObject => NoSuchObject,
            Self::NoSuchInstance => NoSuchInstance,
            Self::GetRequest(b) => GetRequest(AsnReader::from_bytes(b)),
            Self::GetNextRequest(b) => GetNextRequest(AsnReader::from_bytes(b)),
            Self::GetBulkRequest(b) => GetBulkRequest(AsnReader::from_bytes(b)),
            Self::Response(b) => Response(AsnReader::from_bytes(b)),
            Self::SetRequest(b) => SetRequest(AsnReader::from_bytes(b)),
            Self::InformRequest(b) => InformRequest(AsnReader::from_bytes(b)),
            Self::Trap(b) => Trap(AsnReader::from_bytes(b)),
            Self::Report(b) => Report(AsnReader::from_bytes(b)),
        }
    }
}

impl PartialEq for OwnedValue {
    fn eq(&self, other: &Self) -> bool {
        use ValueBuf::*;
        match (self, other) {
            (Boolean(a), Boolean(b)) => a == b,
            (Null, Null) => true,
            (Integer(a), Integer(b)) => a == b,
            (OctetString(a), OctetString(b)) => a == b,
            (ObjectIdentifier(a), ObjectIdentifier(b)) => a == b,
            (Sequence(a), Sequence(b)) => a == b,
            (Set(a), Set(b)) => a == b,
            (Constructed(i1, a), Constructed(i2, b)) => i1 == i2 && a == b,
            (IpAddress(a), IpAddress(b)) => a == b,
            (Counter32(a), Counter32(b)) => a == b,
            (Unsigned32(a), Unsigned32(b)) => a == b,
            (Timeticks(a), Timeticks(b)) => a == b,
            (Opaque(a), Opaque(b)) => a == b,
            (Counter64(a), Counter64(b)) => a == b,
            (EndOfMibView, EndOfMibView)
            | (NoSuchObject, NoSuchObject)
            | (NoSuchInstance, NoSuchInstance) => true,
            (GetRequest(a), GetRequest(b))
            | (GetNextRequest(a), GetNextRequest(b))
            | (GetBulkRequest(a), GetBulkRequest(b))
            | (Response(a), Response(b))
            | (SetRequest(a), SetRequest(b))
            | (InformRequest(a), InformRequest(b))
            | (Trap(a), Trap(b))
            | (Report(a), Report(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for OwnedValue {}

impl fmt::Debug for OwnedValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_value().fmt(f)
    }
}

impl From<&Value<'_>> for OwnedValue {
    fn from(value: &Value<'_>) -> Self {
        match value {
            Value::Boolean(v) => Self::Boolean(*v),
            Value::Null => Self::Null,
            Value::Integer(n) => Self::Integer(*n),
            Value::OctetString(s) => Self::OctetString(s.to_vec()),
            Value::ObjectIdentifier(oid) => Self::ObjectIdentifier(oid.to_owned()),
            Value::Sequence(r) => Self::Sequence(r.as_bytes().to_vec()),
            Value::Set(r) => Self::Set(r.as_bytes().to_vec()),
            Value::Constructed(ident, r) => Self::Constructed(*ident, r.as_bytes().to_vec()),
            Value::IpAddress(a) => Self::IpAddress(*a),
            Value::Counter32(v) => Self::Counter32(*v),
            Value::Unsigned32(v) => Self::Unsigned32(*v),
            Value::Timeticks(v) => Self::Timeticks(*v),
            Value::Opaque(b) => Self::Opaque(b.to_vec()),
            Value::Counter64(v) => Self::Counter64(*v),
            Value::EndOfMibView => Self::EndOfMibView,
            Value::NoSuchObject => Self::NoSuchObject,
            Value::NoSuchInstance => Self::NoSuchInstance,
            Value::GetRequest(r) => Self::GetRequest(r.as_bytes().to_vec()),
            Value::GetNextRequest(r) => Self::GetNextRequest(r.as_bytes().to_vec()),
            Value::GetBulkRequest(r) => Self::GetBulkRequest(r.as_bytes().to_vec()),
            Value::Response(r) => Self::Response(r.as_bytes().to_vec()),
            Value::SetRequest(r) => Self::SetRequest(r.as_bytes().to_vec()),
            Value::InformRequest(r) => Self::InformRequest(r.as_bytes().to_vec()),
            Value::Trap(r) => Self::Trap(r.as_bytes().to_vec()),
            Value::Report(r) => Self::Report(r.as_bytes().to_vec()),
        }
    }
}

impl Value<'_> {
    /// Copy into an [`OwnedValue`] that does not borrow the session buffer.
    pub fn to_owned(&self) -> OwnedValue {
        OwnedValue::from(self)
    }
}

impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Value::Boolean(v) => write!(f, "BOOLEAN: {}", v),
            Value::Integer(n) => write!(f, "INTEGER: {}", n),
            Value::OctetString(slice) => {
                write!(f, "OCTET STRING: {}", String::from_utf8_lossy(slice))
            }
            Value::ObjectIdentifier(ref obj_id) => write!(f, "OBJECT IDENTIFIER: {}", obj_id),
            Value::Null => write!(f, "NULL"),
            Value::Sequence(ref val) => write!(f, "SEQUENCE: {:#?}", val),
            Value::Set(ref val) => write!(f, "SET: {:?}", val),
            Value::Constructed(ident, ref val) => write!(f, "CONSTRUCTED-{}: {:#?}", ident, val),
            Value::IpAddress(val) => {
                write!(f, "IP ADDRESS: {}.{}.{}.{}", val[0], val[1], val[2], val[3])
            }
            Value::Counter32(val) => write!(f, "COUNTER32: {}", val),
            Value::Unsigned32(val) => write!(f, "UNSIGNED32: {}", val),
            Value::Timeticks(val) => write!(f, "TIMETICKS: {}", val),
            Value::Opaque(val) => write!(f, "OPAQUE: {:?}", val),
            Value::Counter64(val) => write!(f, "COUNTER64: {}", val),
            Value::EndOfMibView => write!(f, "END OF MIB VIEW"),
            Value::NoSuchObject => write!(f, "NO SUCH OBJECT"),
            Value::NoSuchInstance => write!(f, "NO SUCH INSTANCE"),
            Value::GetRequest(ref val) => write!(f, "SNMP GET REQUEST: {:#?}", val),
            Value::GetNextRequest(ref val) => write!(f, "SNMP GET NEXT REQUEST: {:#?}", val),
            Value::GetBulkRequest(ref val) => write!(f, "SNMP GET BULK REQUEST: {:#?}", val),
            Value::Response(ref val) => write!(f, "SNMP RESPONSE: {:#?}", val),
            Value::SetRequest(ref val) => write!(f, "SNMP SET REQUEST: {:#?}", val),
            Value::InformRequest(ref val) => write!(f, "SNMP INFORM REQUEST: {:#?}", val),
            Value::Trap(ref val) => write!(f, "SNMP TRAP: {:#?}", val),
            Value::Report(ref val) => write!(f, "SNMP REPORT: {:#?}", val),
        }
    }
}

fn zero_len(val: &[u8]) -> Result<&[u8]> {
    if val.is_empty() {
        Ok(val)
    } else {
        Err(Error::AsnInvalidLen)
    }
}

impl<'a> Iterator for AsnReader<'a> {
    type Item = Value<'a>;

    fn next(&mut self) -> Option<Value<'a>> {
        if let Ok(ident) = self.peek_byte() {
            let ret: Result<Value> = match ident {
                asn1::TYPE_BOOLEAN => self.read_asn_boolean().map(Value::Boolean),
                asn1::TYPE_NULL => self.read_asn_null().map(|()| Value::Null),
                asn1::TYPE_INTEGER => self.read_asn_integer().map(Value::Integer),
                asn1::TYPE_OCTETSTRING => self.read_asn_octetstring().map(Value::OctetString),
                asn1::TYPE_OBJECTIDENTIFIER => self
                    .read_asn_objectidentifier()
                    .map(Value::ObjectIdentifier),
                asn1::TYPE_SEQUENCE => self
                    .read_raw(ident)
                    .map(|v| Value::Sequence(AsnReader::from_bytes(v))),
                asn1::TYPE_SET => self
                    .read_raw(ident)
                    .map(|v| Value::Set(AsnReader::from_bytes(v))),
                snmp::TYPE_IPADDRESS => self.read_snmp_ipaddress().map(Value::IpAddress),
                snmp::TYPE_COUNTER32 => self.read_snmp_counter32().map(Value::Counter32),
                snmp::TYPE_UNSIGNED32 => self.read_snmp_unsigned32().map(Value::Unsigned32),
                snmp::TYPE_TIMETICKS => self.read_snmp_timeticks().map(Value::Timeticks),
                snmp::TYPE_OPAQUE => self.read_snmp_opaque().map(Value::Opaque),
                snmp::TYPE_COUNTER64 => self.read_snmp_counter64().map(Value::Counter64),
                snmp::MSG_GET => self
                    .read_raw(ident)
                    .map(|v| Value::GetRequest(AsnReader::from_bytes(v))),
                snmp::MSG_GET_NEXT => self
                    .read_raw(ident)
                    .map(|v| Value::GetNextRequest(AsnReader::from_bytes(v))),
                snmp::MSG_GET_BULK => self
                    .read_raw(ident)
                    .map(|v| Value::GetBulkRequest(AsnReader::from_bytes(v))),
                snmp::MSG_RESPONSE => self
                    .read_raw(ident)
                    .map(|v| Value::Response(AsnReader::from_bytes(v))),
                snmp::MSG_SET => self
                    .read_raw(ident)
                    .map(|v| Value::SetRequest(AsnReader::from_bytes(v))),
                snmp::MSG_INFORM => self
                    .read_raw(ident)
                    .map(|v| Value::InformRequest(AsnReader::from_bytes(v))),
                snmp::MSG_TRAP => self
                    .read_raw(ident)
                    .map(|v| Value::Trap(AsnReader::from_bytes(v))),
                snmp::MSG_REPORT => self
                    .read_raw(ident)
                    .map(|v| Value::Report(AsnReader::from_bytes(v))),
                snmp::SNMP_ENDOFMIBVIEW => self
                    .read_raw(ident)
                    .and_then(zero_len)
                    .map(|_v| Value::EndOfMibView),
                snmp::SNMP_NOSUCHOBJECT => self
                    .read_raw(ident)
                    .and_then(zero_len)
                    .map(|_v| Value::NoSuchObject),
                snmp::SNMP_NOSUCHINSTANCE => self
                    .read_raw(ident)
                    .and_then(zero_len)
                    .map(|_v| Value::NoSuchInstance),
                ident if ident & asn1::CONSTRUCTED == asn1::CONSTRUCTED => self
                    .read_raw(ident)
                    .map(|v| Value::Constructed(ident, AsnReader::from_bytes(v))),
                _ => Err(Error::AsnUnsupportedType),
            };
            ret.ok()
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone, Eq)]
pub enum MessageType {
    GetRequest,
    GetNextRequest,
    GetBulkRequest,
    Response,
    SetRequest,
    InformRequest,
    Trap,
    TrapV1,
    Report,
}

impl MessageType {
    pub fn from_ident(ident: u8) -> Result<MessageType> {
        Ok(match ident {
            snmp::MSG_GET => MessageType::GetRequest,
            snmp::MSG_GET_NEXT => MessageType::GetNextRequest,
            snmp::MSG_GET_BULK => MessageType::GetBulkRequest,
            snmp::MSG_RESPONSE => MessageType::Response,
            snmp::MSG_SET => MessageType::SetRequest,
            snmp::MSG_INFORM => MessageType::InformRequest,
            snmp::MSG_TRAP => MessageType::Trap,
            snmp::MSG_REPORT => MessageType::Report,
            snmp::MSG_TRAP_V1 => MessageType::TrapV1,
            _ => return Err(Error::AsnWrongType),
        })
    }
}

#[derive(Clone)]
pub struct Varbinds<'a> {
    inner: AsnReader<'a>,
}

impl fmt::Debug for Varbinds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // f.debug_list().entries(self.clone()).finish()
        let mut ds = f.debug_struct("Varbinds");
        for (name, val) in self.clone() {
            ds.field(&format!("{}", name), &format!("{:?}", val));
        }
        ds.finish()
    }
}

impl<'a> Varbinds<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Varbinds<'a> {
        Varbinds {
            inner: AsnReader::from_bytes(bytes),
        }
    }

    /// Collect all varbinds into owned OID/value pairs that outlive the buffer.
    pub fn to_owned_vec(self) -> Vec<OwnedVarbind> {
        self.map(|(oid, value)| (oid.to_owned(), value.to_owned()))
            .collect()
    }
}

impl<'a> Iterator for Varbinds<'a> {
    type Item = (Oid<'a>, Value<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(seq) = self.inner.read_raw(asn1::TYPE_SEQUENCE) {
            let mut pair = AsnReader::from_bytes(seq);
            if let (Ok(name), Some(value)) = (pair.read_asn_objectidentifier(), pair.next()) {
                return Some((name, value));
            }
        }
        None
    }
}
