use core::fmt;

use bech32::{
    primitives::{
        decode::CheckedHrpstring,
        iter::{ByteIterExt, Fe32IterExt},
        Bech32m,
    },
    Fe32, Hrp,
};
use secp256k1::PublicKey;

#[derive(Debug)]
pub enum Error {
    GenericError(String),
    InvalidAddress(String),
    Secp256k1Error(secp256k1::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::GenericError(msg) => write!(f, "{}", msg),
            Error::InvalidAddress(msg) => write!(f, "{}", msg),
            Error::Secp256k1Error(e) => e.fmt(f),
        }
    }
}

impl From<bech32::primitives::decode::CheckedHrpstringError> for Error {
    fn from(e: bech32::primitives::decode::CheckedHrpstringError) -> Self {
        Error::InvalidAddress(e.to_string())
    }
}

impl From<bech32::DecodeError> for Error {
    fn from(e: bech32::DecodeError) -> Self {
        Error::InvalidAddress(e.to_string())
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::Secp256k1Error(e)
    }
}

impl std::error::Error for Error {}

/// The network format used for this silent payment address.
///
/// There are three network types: Mainnet (`sp1..`), Testnet (`tsp1..`), and Regtest (`sprt1..`).
/// Signet uses the same network type as Testnet.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

/// A silent payment address struct that can be used to deserialize a silent payment address string.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    version: u8,
    scan_pubkey: PublicKey,
    m_pubkey: PublicKey,
    network: Network,
}

impl SilentPaymentAddress {
    pub fn new(
        scan_pubkey: PublicKey,
        m_pubkey: PublicKey,
        network: Network,
        version: u8,
    ) -> Result<Self, Error> {
        if version != 0 {
            return Err(Error::GenericError(
                "Can't have other version than 0 for now".to_owned(),
            ));
        }

        Ok(SilentPaymentAddress {
            scan_pubkey,
            m_pubkey,
            network,
            version,
        })
    }

    pub fn validate_version(version: u8, data_len: usize) -> Result<u8, Error> {
        match version {
            0 => {
                if data_len != 66 {
                    Err(Error::InvalidAddress(
                        "Data length should be 66 bytes for version 0 addresses.".to_string(),
                    ))
                } else {
                    Ok(version)
                }
            }
            31 => Err(Error::InvalidAddress(
                "Backward incompatible version.".to_string(),
            )),
            1..=31u8 => {
                if data_len < 66 {
                    Err(Error::InvalidAddress(
                        "Data length is too short.".to_string(),
                    ))
                } else {
                    Ok(version)
                }
            }
            _ => Err(Error::InvalidAddress("Not supported version".to_string())),
        }
    }

    pub fn get_scan_key(&self) -> PublicKey {
        self.scan_pubkey
    }

    pub fn get_spend_key(&self) -> PublicKey {
        self.m_pubkey
    }

    pub fn get_network(&self) -> Network {
        self.network
    }
}

impl fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", <SilentPaymentAddress as Into<String>>::into(*self))
    }
}

impl TryFrom<&str> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: &str) -> Result<Self, Error> {
        let checked_hrpstring = CheckedHrpstring::new::<Bech32m>(addr)?;
        let hrp = checked_hrpstring.hrp();
        let mut data_with_version = checked_hrpstring.fe32_iter::<&mut dyn Iterator<Item = u8>>();

        let version = data_with_version.nth(0).into_iter().collect::<Vec<_>>()[0].to_u8();
        let data = data_with_version.fes_to_bytes().collect::<Vec<u8>>();
        let checked_version = SilentPaymentAddress::validate_version(version, data.len())?;

        let network = match hrp.as_str() {
            "sp" => Network::Mainnet,
            "tsp" => Network::Testnet,
            "sprt" => Network::Regtest,
            _ => {
                return Err(Error::InvalidAddress(format!(
                    "Wrong prefix, expected \"sp\", \"tsp\", or \"sprt\", got \"{}\"",
                    &hrp
                )))
            }
        };

        let scan_pubkey = PublicKey::from_slice(&data[..33])?;
        let m_pubkey = PublicKey::from_slice(&data[33..66])?;

        SilentPaymentAddress::new(scan_pubkey, m_pubkey, network, checked_version)
    }
}

impl TryFrom<String> for SilentPaymentAddress {
    type Error = Error;

    fn try_from(addr: String) -> Result<Self, Error> {
        addr.as_str().try_into()
    }
}

impl From<SilentPaymentAddress> for String {
    fn from(val: SilentPaymentAddress) -> Self {
        let hrp = match val.network {
            Network::Testnet => "tsp",
            Network::Regtest => "sprt",
            Network::Mainnet => "sp",
        };
        let hrp = Hrp::parse_unchecked(hrp);

        let scan_key_bytes = val.scan_pubkey.serialize();
        let tweaked_spend_pubkey_bytes = val.m_pubkey.serialize();

        let data = [scan_key_bytes, tweaked_spend_pubkey_bytes].concat();

        let version = [val.version]
            .iter()
            .copied()
            .bytes_to_fes()
            .collect::<Vec<Fe32>>()[0];

        data.iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version)
            .chars()
            .collect::<String>()
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
    fn silent_payment_address_v0_is_parsed_correctly() {
        let sp_address = SilentPaymentAddress::try_from(TEST_ADDRESS).expect("should parse");
        assert_eq!(sp_address.get_scan_key().to_string(), SCAN_KEY);
        assert_eq!(sp_address.get_spend_key().to_string(), TWEAKED_SPEND_KEY);
    }

    #[test]
    fn silent_payment_address_v0_is_encoded_correctly() {
        let expected_sp_address = SilentPaymentAddress {
            version: 0,
            scan_pubkey: PublicKey::from_str(SCAN_KEY).unwrap(),
            m_pubkey: PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap(),
            network: Network::Mainnet,
        };
        let ser_address = String::from(expected_sp_address);
        assert_eq!(&ser_address, TEST_ADDRESS);
    }

    #[test]
    fn silent_payment_address_v1_or_greater_drops_extra_data_but_is_not_supported() {
        let scan_pubkey = PublicKey::from_str(SCAN_KEY).unwrap();
        let m_pubkey = PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap();
        let extra_data = [1u8; 33];
        let data = [scan_pubkey.serialize(), m_pubkey.serialize(), extra_data].concat();
        let version_1 = Fe32::P;
        let hrp = Hrp::parse_unchecked("tsp");
        let sp_v1_address = data
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version_1)
            .chars()
            .collect::<String>();
        // Address is parsed correctly, but as version 1 is not supported, SilentPaymentAddress is
        // not created and construction fails
        SilentPaymentAddress::try_from(sp_v1_address)
            .expect_err("Can't have other version than 0 for now");
    }

    #[test]
    fn silent_payment_address_v1_or_greater_fails_early_when_data_is_short() {
        let scan_pubkey = PublicKey::from_str(SCAN_KEY).unwrap();
        let m_pubkey = PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap();
        let data = [scan_pubkey.serialize(), m_pubkey.serialize()].concat();
        let version_1 = Fe32::P;
        let hrp = Hrp::parse_unchecked("tsp");
        let wrong_sp_v1_address = data[..60]
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version_1)
            .chars()
            .collect::<String>();
        SilentPaymentAddress::try_from(wrong_sp_v1_address).expect_err("Data length is too short.");
    }

    #[test]
    fn silent_payment_address_v0_fails_early_when_data_length_is_not_66() {
        let scan_pubkey = PublicKey::from_str(SCAN_KEY).unwrap();
        let m_pubkey = PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap();
        let data = [scan_pubkey.serialize(), m_pubkey.serialize()].concat();
        let version_0 = Fe32::Q;
        let hrp = Hrp::parse_unchecked("tsp");
        let wrong_sp_v0_address = data[..60]
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version_0)
            .chars()
            .collect::<String>();
        SilentPaymentAddress::try_from(wrong_sp_v0_address)
            .expect_err("Data length should be 66 bytes for version 0 addresses.");
    }

    #[test]
    fn silent_payment_address_v31_fails_early_because_is_not_backward_compatible() {
        let scan_pubkey = PublicKey::from_str(SCAN_KEY).unwrap();
        let m_pubkey = PublicKey::from_str(TWEAKED_SPEND_KEY).unwrap();
        let data = [scan_pubkey.serialize(), m_pubkey.serialize()].concat();
        let version_31 = Fe32::L;
        let hrp = Hrp::parse_unchecked("tsp");
        let incompatible_sp_v31_address = data
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version_31)
            .chars()
            .collect::<String>();
        SilentPaymentAddress::try_from(incompatible_sp_v31_address)
            .expect_err("Not supported version");
    }
}
