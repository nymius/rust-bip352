use crate::utils::code::fmt;
use crate::utils::code::Network;
use crate::utils::code::SilentPaymentHrp;

/// Silent payment code parsing error
#[derive(Debug)]
pub enum ParseError {
    /// Bech32 decoding error
    Bech32(bech32::primitives::decode::CheckedHrpstringError),
    /// Version does not comply with spec
    Version(VersionError),
    /// The human readable prefix is not supported for silent payments
    UnknownHrp(UnknownHrpError),
    /// Some public key couldn't be derived from the provided payload
    InvalidPubKey(secp256k1::Error),
    /// Silent payment code's network differs from required one
    UnknownNetwork(NetworkError),
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseError::*;

        match *self {
            Bech32(ref e) => Some(e),
            Version(ref e) => Some(e),
            UnknownHrp(ref e) => Some(e),
            InvalidPubKey(ref e) => Some(e),
            UnknownNetwork(ref e) => Some(e),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseError::*;

        match *self {
            Bech32(ref e) => e.fmt(f),
            Version(ref e) => e.fmt(f),
            UnknownHrp(ref e) => e.fmt(f),
            InvalidPubKey(ref e) => e.fmt(f),
            UnknownNetwork(ref e) => e.fmt(f),
        }
    }
}

impl From<UnknownHrpError> for ParseError {
    fn from(e: UnknownHrpError) -> Self {
        Self::UnknownHrp(e)
    }
}

impl From<VersionError> for ParseError {
    fn from(e: VersionError) -> Self {
        Self::Version(e)
    }
}

impl From<bech32::primitives::decode::CheckedHrpstringError> for ParseError {
    fn from(e: bech32::primitives::decode::CheckedHrpstringError) -> Self {
        Self::Bech32(e)
    }
}

impl From<secp256k1::Error> for ParseError {
    fn from(e: secp256k1::Error) -> Self {
        Self::InvalidPubKey(e)
    }
}

impl From<NetworkError> for ParseError {
    fn from(e: NetworkError) -> Self {
        Self::UnknownNetwork(e)
    }
}

/// Unknown HRP error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownHrpError(pub String);

impl fmt::Display for UnknownHrpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unknown hrp: {}", self.0)
    }
}

impl std::error::Error for UnknownHrpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Silent payment error related to versions
#[derive(Debug)]
pub enum VersionError {
    /// Silent payment v31 code. It is not backward compatible
    BackwardIncompatibleVersion,
    /// The length of the payload doesn't match the version of the code
    WrongPayloadLength,
    /// The version provided is greater than 31 or is not supported by the current code
    NotSupported,
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use VersionError::*;

        match *self {
            BackwardIncompatibleVersion => {
                write!(f, "version 31 codes are not backward compatible")
            }
            WrongPayloadLength => write!(f, "payload length does not match version spec"),
            NotSupported => write!(f, "unsupported version"),
        }
    }
}

impl std::error::Error for VersionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Address's network differs from required one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkError {
    /// Network that was required.
    pub required: Network,
    /// The address itself.
    pub allowed: SilentPaymentHrp,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "expected: {} - allowed: {}",
            &self.required, &self.allowed
        )
    }
}

impl std::error::Error for NetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
