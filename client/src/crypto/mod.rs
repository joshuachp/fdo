use coset::CoseEncrypt0;

use crate::protocol::v101::hash_hmac::{HMac, Hash};
use crate::protocol::v101::public_key::{PkEnc, PkType};

pub(crate) mod software;
#[cfg(feature = "tpm")]
pub(crate) mod tpm;

pub(crate) trait Crypto {
    /// Public key encoding
    const PK_ENC: PkEnc;

    /// Public key type
    fn pk_type(&mut self) -> PkType;

    /// Create and sing a CSR with the CN of the device info
    async fn csr(&mut self, device_info: &str) -> eyre::Result<Vec<u8>>;

    /// Create a hmac_secret and return an encrypted version.
    async fn hmac_secret(&mut self) -> eyre::Result<CoseEncrypt0>;

    /// Singes the header using the provided encrypted secret.
    async fn hmac(
        &mut self,
        enc_secret: &CoseEncrypt0,
        header: &[u8],
    ) -> eyre::Result<HMac<'static>>;

    fn hash(&mut self, data: &[u8]) -> eyre::Result<Hash<'static>>;
}
