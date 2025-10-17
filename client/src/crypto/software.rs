use std::borrow::Cow;

use aws_lc_rs::rand::SystemRandom;
use rcgen::{CertificateParams, DistinguishedName, DnType};
use serde_bytes::ByteBuf;

use crate::protocol::v101::hash_hmac::{HMac, Hash, Hashtype};
use crate::protocol::v101::public_key::{PkEnc, PkType};

use super::Crypto;

pub(crate) struct SoftwareCrypto {
    device_keys: rcgen::KeyPair,
    rand: SystemRandom,
}

impl SoftwareCrypto {
    pub(crate) fn create() -> eyre::Result<Self> {
        let device_keys = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

        Ok(Self { device_keys, rand })
    }
}

impl Crypto for SoftwareCrypto {
    const PK_ENC: PkEnc = PkEnc::X509;

    fn pk_type(&mut self) -> PkType {
        PkType::Secp256R1
    }

    fn csr(&mut self, device_info: &str) -> eyre::Result<Vec<u8>> {
        // The device info for the certificate
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, device_info);

        let mut csr_param = CertificateParams::new([])?;
        csr_param.distinguished_name = dn;

        // Singed CSR
        let csr = csr_param.serialize_request(&self.device_keys)?;

        Ok(csr.der().to_vec())
    }

    fn hmac(&mut self, data: &[u8]) -> eyre::Result<HMac<'static>> {
        let key = aws_lc_rs::hmac::Key::new(
            aws_lc_rs::hmac::HMAC_SHA256,
            self.device_keys.serialized_der(),
        );

        let tag = aws_lc_rs::hmac::sign(&key, data);

        Ok(HMac {
            hashtype: Hashtype::Sha256,
            hash: Cow::Owned(ByteBuf::from(tag.as_ref())),
        })
    }

    fn hash(&mut self, data: &[u8]) -> eyre::Result<Hash<'static>> {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);

        Ok(Hash {
            hashtype: Hashtype::Sha256,
            hash: Cow::Owned(ByteBuf::from(digest.as_ref())),
        })
    }
}
