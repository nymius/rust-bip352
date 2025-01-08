use std::fmt::Error;

use bitcoin::hashes::Hash;
use bitcoin::hex::fmt_hex_exact;
use bitcoin::OutPoint;

/// Wrapper struct of [bitcoin::OutPoint] which displays itself as txid || vout in little endian
/// order. Implements [Ord] using lexicographic order.
#[derive(Eq, Debug)]
pub struct SilentPaymentOutpoint(pub OutPoint);

impl SilentPaymentOutpoint {
    /// Get the inner byte array represented in little endian. Convenience method to use with
    /// [secp256k1::silentpayments] methods.
    pub fn as_byte_array(&self) -> [u8; 36] {
        let mut outpoint: [u8; 36] = [0u8; 36];
        outpoint[..32].clone_from_slice(self.0.txid.to_raw_hash().as_byte_array());
        outpoint[32..36].clone_from_slice(&self.0.vout.to_le_bytes());
        outpoint
    }
}

impl std::fmt::Display for SilentPaymentOutpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), Error> {
        fmt_hex_exact!(f, 36, self.as_byte_array(), bitcoin::hex::Case::Lower)
    }
}

impl PartialEq for SilentPaymentOutpoint {
    fn eq(&self, other: &Self) -> bool {
        // TODO: implement this with less allocations
        self.to_string().as_str().eq(other.to_string().as_str())
    }
}

impl PartialOrd for SilentPaymentOutpoint {
    fn partial_cmp(&self, other: &Self) -> std::option::Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SilentPaymentOutpoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // TODO: implement this with less allocations
        self.to_string().as_str().cmp(other.to_string().as_str())
    }
}

impl From<OutPoint> for SilentPaymentOutpoint {
    fn from(v: OutPoint) -> Self {
        Self(v)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn representation_is_little_endian() {
        let expected_sp_outpoint_representation =
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945605000000";
        let outpoint_str = "56944c5d3f98413ef45cf54545538103cc9f298e0575820ad3591376e2e0f65d:5";
        let out_point = OutPoint::from_str(outpoint_str).unwrap();
        let sp_outpoint = SilentPaymentOutpoint(out_point);
        assert_eq!(
            expected_sp_outpoint_representation,
            sp_outpoint.to_string().as_str()
        );
        assert_eq!(outpoint_str, out_point.to_string().as_str());
    }

    #[test]
    fn order_is_lexicographic_for_little_endian_representation() {
        let sp_out_0 = SilentPaymentOutpoint(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0",
            )
            .unwrap(),
        );
        let sp_out_1 = SilentPaymentOutpoint(
            OutPoint::from_str(
                "fea98f4cf220bc103ab9a0ed43d8e8c2e450c45dfaae9f27e4b4a30a280f08e9:52",
            )
            .unwrap(),
        );
        let sp_out_2 = SilentPaymentOutpoint(
            OutPoint::from_str(
                "b76163cbc889af6612f2460e45038614098d9442fe5c61c37b0332004fc6e2e3:1",
            )
            .unwrap(),
        );
        let sp_out_3 = SilentPaymentOutpoint(
            OutPoint::from_str(
                "40486d8120bf3b7404a80b8c2d1445d21e0702195ccac1088418e50ec2eb01a9:1",
            )
            .unwrap(),
        );

        let mut sp_outpoints = [&sp_out_1, &sp_out_3, &sp_out_2, &sp_out_0];

        sp_outpoints.sort();

        assert_eq!(sp_outpoints[0], &sp_out_0);
        assert_eq!(sp_outpoints[1], &sp_out_3);
        assert_eq!(sp_outpoints[2], &sp_out_2);
        assert_eq!(sp_outpoints[3], &sp_out_1);
    }
}
