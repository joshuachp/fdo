use crate::protocol::v101::hash_hmac::{HMac, Hash};
use crate::protocol::v101::public_key::{PkEnc, PkType};

pub(crate) mod software;

pub(crate) trait Crypto {
    const PK_ENC: PkEnc;

    fn pk_type(&mut self) -> PkType;

    fn csr(&mut self, device_info: &str) -> eyre::Result<Vec<u8>>;

    fn hmac(&mut self, header: &[u8]) -> eyre::Result<HMac<'static>>;

    fn hash(&mut self, data: &[u8]) -> eyre::Result<Hash<'static>>;
}
