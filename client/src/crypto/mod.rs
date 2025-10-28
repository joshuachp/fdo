use coset::{CoseEncrypt0, CoseSign1};

use crate::protocol::v101::hash_hmac::{HMac, Hash};
use crate::protocol::v101::public_key::{PkEnc, PkType};
use crate::protocol::v101::sign_info::DeviceSgType;

pub(crate) mod software;
#[cfg(feature = "tpm")]
pub(crate) mod tpm;

pub(crate) trait Crypto {
    /// Public key encoding
    const PK_ENC: PkEnc;

    /// Public key type
    fn pk_type(&mut self) -> PkType;

    fn sign_info_type(&self) -> DeviceSgType;

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

    async fn sign(&mut self, data: &[u8]) -> eyre::Result<Vec<u8>>;

    fn hash(&mut self, data: &[u8]) -> eyre::Result<Hash<'static>>;

    async fn cose_sing(&mut self, payload: Vec<u8>) -> eyre::Result<CoseSign1>;
}
