pub mod error;

pub use self::error::{NetworkError, ParseError, UnknownHrpError, VersionError};

use core::fmt;
use core::marker::PhantomData;

use bitcoin::{
    bech32::{
        primitives::{
            decode::{AsciiToFe32Iter, CheckedHrpstring},
            iter::{ByteIterExt, Fe32IterExt},
            Bech32m,
        },
        Fe32, Hrp,
    },
    Network,
};
use secp256k1::{
    ffi::{CPtr, SilentpaymentsRecipient},
    PublicKey,
};

/// Human readable prefix for encoding bitcoin Mainnet silent payment codes
pub const SP: Hrp = Hrp::parse_unchecked("sp");
/// Human readable prefix for encoding bitcoin Testnet (3 or 4) or Signet silent payment codes
pub const TSP: Hrp = Hrp::parse_unchecked("tsp");
/// Human readable prefix for encoding bitcoin regtest silent payment codes
pub const SPRT: Hrp = Hrp::parse_unchecked("sprt");

mod sealed {
    pub trait NetworkValidation {}
    pub trait VersionValidation {}
    impl VersionValidation for super::VersionStrict {}
    impl VersionValidation for super::VersionCompatible {}
    impl NetworkValidation for super::NetworkChecked {}
    impl NetworkValidation for super::NetworkUnchecked {}
}

/// Marker of status of code's network validation. Same as with [`bitcoin::Address`].
/// Implemented identical to mantain the same code ergonomics
pub trait NetworkValidation: sealed::NetworkValidation + Sync + Send + Sized + Unpin {
    /// Indicates whether this `NetworkValidation` is `NetworkChecked` or not.
    const IS_CHECKED: bool;
}

/// Marker that code's network has been successfully validated. Same as with [`bitcoin::Address`].
/// Implemented identical to mantain the same code ergonomics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkChecked {}

/// Marker that code's network has not yet been validated. Same as with [`bitcoin::Address`].
/// Implemented identical to mantain the same code ergonomics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkUnchecked {}

impl NetworkValidation for NetworkChecked {
    const IS_CHECKED: bool = true;
}
impl NetworkValidation for NetworkUnchecked {
    const IS_CHECKED: bool = false;
}

/// Trait to identify the desired version validation of the silent payment code.
pub trait VersionValidation: sealed::VersionValidation + Sync + Send + Sized + Unpin {
    fn process_payload(payload: AsciiToFe32Iter) -> Result<(u8, Vec<u8>), ParseError>;
}

/// Marker that code's validation is strict, i.e., trying to parse a silent payment codes of higher
/// versions than the currently supported ones will fail.
/// The current only supported version is 0.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VersionStrict {}

/// Marker that code's validation is compatible, i.e., trying to parse a silent payment codes of higher
/// versions than the currently supported ones will drop data, but still get the needed data
/// portions to support the current version.
/// The current only supported version is 0.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VersionCompatible {}

impl VersionValidation for VersionStrict {
    fn process_payload(mut payload: AsciiToFe32Iter) -> Result<(u8, Vec<u8>), ParseError> {
        let version = payload.nth(0).into_iter().collect::<Vec<_>>()[0].to_u8();
        let data = match version {
            0 => {
                let data = payload.fes_to_bytes().collect::<Vec<u8>>();
                if data.len() != 66 {
                    return Err(VersionError::WrongPayloadLength)?;
                } else {
                    data
                }
            }
            31 => return Err(VersionError::BackwardIncompatibleVersion)?,
            _ => return Err(VersionError::NotSupported)?,
        };
        Ok((version, data))
    }
}

impl VersionValidation for VersionCompatible {
    fn process_payload(mut payload: AsciiToFe32Iter) -> Result<(u8, Vec<u8>), ParseError> {
        let version = payload.nth(0).into_iter().collect::<Vec<_>>()[0].to_u8();
        let data = match version {
            0 => {
                let data = payload.fes_to_bytes().collect::<Vec<u8>>();
                if data.len() != 66 {
                    return Err(VersionError::WrongPayloadLength)?;
                } else {
                    data
                }
            }
            31 => return Err(VersionError::BackwardIncompatibleVersion)?,
            1..=31u8 => {
                let data = payload.fes_to_bytes().take(66).collect::<Vec<u8>>();
                if data.len() < 66 {
                    return Err(VersionError::WrongPayloadLength)?;
                } else {
                    data
                }
            }
            _ => return Err(VersionError::NotSupported)?,
        };
        Ok((0u8, data))
    }
}

/// The inner representation of a silent payment code
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SilentPaymentInner {
    /// The scanning public key from a silent payment code
    scan_pubkey: PublicKey,
    /// The spending public key from a silent payment code. Could be labelled.
    spend_pubkey: PublicKey,
    /// The network set associated with the human readable prefix of the silent payment code
    hrp: SilentPaymentHrp,
    /// The version of the silent payment. Currently the only supported one is version 0
    version: u8,
}

impl SilentPaymentInner {
    pub fn new(
        scan_pubkey: PublicKey,
        spend_pubkey: PublicKey,
        hrp: SilentPaymentHrp,
        version: u8,
    ) -> Self {
        SilentPaymentInner {
            scan_pubkey,
            spend_pubkey,
            hrp,
            version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
// The `#[repr(transparent)]` attribute is used to guarantee the layout of the `SilentPaymentCode` struct. It
// is an implementation detail and users should not rely on it in their code.
#[repr(transparent)]
pub struct SilentPaymentCode<V = VersionStrict, N = NetworkChecked>(
    SilentPaymentInner,
    PhantomData<V>,
    PhantomData<N>,
)
where
    V: VersionValidation,
    N: NetworkValidation;

impl<V> SilentPaymentCode<V, NetworkUnchecked>
where
    V: VersionValidation,
{
    /// Check if the silent payment code is valid for the given network.
    pub fn is_valid_for_network(&self, n: Network) -> bool {
        self.0.hrp == SilentPaymentHrp::from_network(n)
    }

    /// Checks whether network of this address is as required.
    #[inline]
    pub fn require_network(self, required: Network) -> Result<SilentPaymentCode, ParseError> {
        if self.is_valid_for_network(required) {
            Ok(self.assume_checked())
        } else {
            Err(NetworkError {
                required,
                allowed: self.0.hrp,
            }
            .into())
        }
    }

    /// Marks, without any additional checks, network of this address as checked.
    ///
    /// Improper use of this method may lead to loss of funds. Reader will most likely prefer
    /// [`require_network`](SilentPaymentCode<V, NetworkUnchecked>::require_network) as a safe variant.
    #[inline]
    pub fn assume_checked(self) -> SilentPaymentCode {
        SilentPaymentCode::new(self.0)
    }
}

impl<V, N> SilentPaymentCode<V, N>
where
    V: VersionValidation,
    N: NetworkValidation,
{
    fn new(inner: SilentPaymentInner) -> Self {
        Self(inner, PhantomData, PhantomData)
    }

    fn create_recipient(self, index: usize) -> SilentpaymentsRecipient {
        SilentpaymentsRecipient::new(
            &unsafe { *self.0.scan_pubkey.as_c_ptr() },
            &unsafe { *self.0.spend_pubkey.as_c_ptr() },
            index,
        )
    }
}

impl TryFrom<&str> for SilentPaymentCode<VersionStrict, NetworkUnchecked> {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<SilentPaymentCode<VersionStrict, NetworkUnchecked>, ParseError> {
        let checked_hrpstring = CheckedHrpstring::new::<Bech32m>(s)?;
        let hrp = checked_hrpstring.hrp();
        let payload = checked_hrpstring.fe32_iter::<&mut dyn Iterator<Item = u8>>();

        let (version, data) = VersionStrict::process_payload(payload)?;
        let silent_payment_hrp = SilentPaymentHrp::from_hrp(hrp)?;
        let scan_pubkey = PublicKey::from_slice(&data[..33])?;
        let spend_pubkey = PublicKey::from_slice(&data[33..66])?;

        Ok(Self::new(SilentPaymentInner::new(
            scan_pubkey,
            spend_pubkey,
            silent_payment_hrp,
            version,
        )))
    }
}

impl TryFrom<&str> for SilentPaymentCode<VersionCompatible, NetworkUnchecked> {
    type Error = ParseError;

    fn try_from(
        s: &str,
    ) -> Result<SilentPaymentCode<VersionCompatible, NetworkUnchecked>, ParseError> {
        let checked_hrpstring = CheckedHrpstring::new::<Bech32m>(s)?;
        let hrp = checked_hrpstring.hrp();
        let payload = checked_hrpstring.fe32_iter::<&mut dyn Iterator<Item = u8>>();

        let (version, data) = VersionCompatible::process_payload(payload)?;
        let silent_payment_hrp = SilentPaymentHrp::from_hrp(hrp)?;
        let scan_pubkey = PublicKey::from_slice(&data[..33])?;
        let spend_pubkey = PublicKey::from_slice(&data[33..66])?;

        Ok(Self::new(SilentPaymentInner::new(
            scan_pubkey,
            spend_pubkey,
            silent_payment_hrp,
            version,
        )))
    }
}

impl fmt::Display for SilentPaymentInner {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let hrp = self.hrp.to_hrp();

        let scan_key_bytes = self.scan_pubkey.serialize();
        let tweaked_spend_pubkey_bytes = self.spend_pubkey.serialize();

        let data = [scan_key_bytes, tweaked_spend_pubkey_bytes].concat();

        let version = [self.version]
            .iter()
            .copied()
            .bytes_to_fes()
            .collect::<Vec<Fe32>>()[0];

        let encoded_silent_payment_code = data
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version)
            .chars()
            .collect::<String>();

        fmt.write_str(&encoded_silent_payment_code)
    }
}

impl fmt::Display for SilentPaymentCode {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

/// The network format used for this silent payment code
///
/// There are three network types: Mainnet (`sp1..`), multiple Testnet implementations (`tsp1..`),
/// and Regtest (`sprt1..`). Signet uses the same network type as Testnet.
///
/// The format is the same as [`bitcoin::address::KnownHrp`], but replicated differently to allow
/// the use of the conversion from the human readable prefix used by silent payment codes
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum SilentPaymentHrp {
    /// The main Bitcoin network.
    Mainnet,
    /// The test networks, testnet (testnet3), testnet4, and signet.
    Testnets,
    /// The regtest network.
    Regtest,
}

impl SilentPaymentHrp {
    /// Constructs a new [`SilentPaymentHrp`] from [`Network`].
    fn from_network(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self::Mainnet,
            Network::Testnet | Network::Testnet4 | Network::Signet => Self::Testnets,
            Network::Regtest => Self::Regtest,
            // Avoid users loosing funds in random networks
            _ => Self::Regtest,
        }
    }

    /// Constructs a new [`SilentPaymentHrp`] from a [`bech32::Hrp`].
    fn from_hrp(hrp: Hrp) -> Result<Self, UnknownHrpError> {
        if hrp == self::SP {
            Ok(Self::Mainnet)
        } else if hrp == self::TSP {
            Ok(Self::Testnets)
        } else if hrp == self::SPRT {
            Ok(Self::Regtest)
        } else {
            Err(UnknownHrpError(hrp.to_lowercase()))
        }
    }

    /// Converts, infallibly a SilentPaymentHrp to a [`bech32::Hrp`].
    fn to_hrp(self) -> Hrp {
        match self {
            Self::Mainnet => self::SP,
            Self::Testnets => self::TSP,
            Self::Regtest => self::SPRT,
        }
    }
}

impl fmt::Display for SilentPaymentHrp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SilentPaymentHrp::*;

        match *self {
            Mainnet => write!(f, "mainnet"),
            Testnets => write!(f, "testnet3, testnet4 and signet"),
            Regtest => write!(f, "regtest"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    const TEST_ADDRESS: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
    const SCAN_KEY: &str = "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4";
    const TWEAKED_SPEND_KEY: &str =
        "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";

    #[test]
    fn silent_payment_code_v0_is_parsed_correctly() {
        let sp_code = SilentPaymentCode::<VersionCompatible, _>::try_from(TEST_ADDRESS)
            .expect("should parse");
        assert_eq!(sp_code.0.scan_pubkey.to_string(), SCAN_KEY);
        assert_eq!(sp_code.0.spend_pubkey.to_string(), TWEAKED_SPEND_KEY);
    }

    #[test]
    fn silent_payment_code_v0_is_encoded_correctly() {
        let expected_sp_code = SilentPaymentCode::new(SilentPaymentInner {
            version: 0,
            scan_pubkey: PublicKey::from_str(SCAN_KEY).unwrap(),
            spend_pubkey: PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap(),
            hrp: SilentPaymentHrp::Mainnet,
        });
        let bech32_encoded_sp_code = expected_sp_code.to_string();
        assert_eq!(&bech32_encoded_sp_code, TEST_ADDRESS);
    }

    #[test]
    fn silent_payment_code_v1_or_greater_drops_extra_data_with_validation_compatible() {
        let scan_pubkey = PublicKey::from_str(SCAN_KEY).unwrap();
        let m_pubkey = PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap();
        let mut data = [1u8; 70];
        data[..33].clone_from_slice(&scan_pubkey.serialize());
        data[33..66].clone_from_slice(&m_pubkey.serialize());
        let version_1 = Fe32::P;
        let hrp = Hrp::parse_unchecked("tsp");
        let sp_v1_code = data
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version_1)
            .chars()
            .collect::<String>();
        let sp_code_bech32_encoded =
            SilentPaymentCode::<VersionCompatible, _>::try_from(sp_v1_code.as_str())
                .expect("silent payment code is parsed correctly");
        assert_eq!(sp_code_bech32_encoded.0.scan_pubkey.to_string(), SCAN_KEY);
        assert_eq!(
            sp_code_bech32_encoded.0.spend_pubkey.to_string(),
            TWEAKED_SPEND_KEY
        );
    }

    #[test]
    fn silent_payment_code_v1_or_greater_fails_with_validation_strict() {
        let scan_pubkey = PublicKey::from_str(SCAN_KEY).unwrap();
        let m_pubkey = PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap();
        let mut data = [1u8; 70];
        data[..33].clone_from_slice(&scan_pubkey.serialize());
        data[33..66].clone_from_slice(&m_pubkey.serialize());
        let version_1 = Fe32::P;
        let hrp = Hrp::parse_unchecked("tsp");
        let sp_v1_code = data
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version_1)
            .chars()
            .collect::<String>();
        SilentPaymentCode::<VersionStrict, _>::try_from(sp_v1_code.as_str())
            .expect_err("payload length does not match version spec");
    }

    #[test]
    fn silent_payment_code_v1_or_greater_fails_early_when_data_is_short() {
        let scan_pubkey = PublicKey::from_str(SCAN_KEY).unwrap();
        let m_pubkey = PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap();
        let data = [scan_pubkey.serialize(), m_pubkey.serialize()].concat();
        let version_1 = Fe32::P;
        let hrp = Hrp::parse_unchecked("tsp");
        let wrong_sp_v1_code = data[..60]
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version_1)
            .chars()
            .collect::<String>();
        SilentPaymentCode::<VersionCompatible, _>::try_from(wrong_sp_v1_code.as_str())
            .expect_err("payload length does not match version spec");
    }

    #[test]
    fn silent_payment_code_v0_fails_early_when_data_length_is_not_66() {
        let scan_pubkey = PublicKey::from_str(SCAN_KEY).unwrap();
        let m_pubkey = PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap();
        let data = [scan_pubkey.serialize(), m_pubkey.serialize()].concat();
        let version_0 = Fe32::Q;
        let hrp = Hrp::parse_unchecked("tsp");
        let wrong_sp_v0_code = data[..60]
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version_0)
            .chars()
            .collect::<String>();
        SilentPaymentCode::<VersionCompatible, _>::try_from(wrong_sp_v0_code.as_str())
            .expect_err("payload length does not match version spec");
    }

    #[test]
    fn silent_payment_code_v31_fails_early_because_is_not_backward_compatible() {
        let scan_pubkey = PublicKey::from_str(SCAN_KEY).unwrap();
        let m_pubkey = PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap();
        let data = [scan_pubkey.serialize(), m_pubkey.serialize()].concat();
        let version_31 = Fe32::L;
        let hrp = Hrp::parse_unchecked("tsp");
        let incompatible_sp_v31_code = data
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version_31)
            .chars()
            .collect::<String>();
        SilentPaymentCode::<VersionCompatible, _>::try_from(incompatible_sp_v31_code.as_str())
            .expect_err("Not supported version");
    }
}
