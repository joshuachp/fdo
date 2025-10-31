use std::borrow::Cow;

use coset::iana::Algorithm as CoseAlgorithm;
use coset::{CoseEncrypt0, CoseSign1, HeaderBuilder};
use eyre::{OptionExt, bail};
use serde_bytes::ByteBuf;
use tracing::debug;

use crate::protocol::v101::Nonce;
use crate::protocol::v101::hash_hmac::{HMac, Hash, Hashtype};
use crate::protocol::v101::key_exchange::{KexSuitNames, XAKeyExchange, XBKeyExchange};
use crate::protocol::v101::public_key::{PkEnc, PkType, PublicKey};
use crate::protocol::v101::sign_info::DeviceSgType;

pub(crate) mod kdf;
pub(crate) mod software;
#[cfg(feature = "tpm")]
pub(crate) mod tpm;

// TODO: this can be simplified, encryption can be done by aws_lc_rs in most cases.
pub(crate) trait Crypto {
    /// Public key encoding
    const PK_ENC: PkEnc;

    /// Public key type
    fn pk_type(&mut self) -> PkType;

    fn sign_info_type(&self) -> DeviceSgType;

    fn kex_suit(&mut self) -> KexSuitNames;

    fn cipher_suite(&mut self) -> CoseAlgorithm;

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

    async fn verify_hmac(
        &mut self,
        ec_secret: &CoseEncrypt0,
        hmac: &HMac<'_>,
        data: &[u8],
    ) -> eyre::Result<()>;

    fn hash(&mut self, data: &[u8]) -> Hash<'static> {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);

        Hash {
            hashtype: Hashtype::Sha256,
            hash: Cow::Owned(ByteBuf::from(digest.as_ref())),
        }
    }

    async fn cose_sing(
        &mut self,
        unprotected: HeaderBuilder,
        payload: Vec<u8>,
    ) -> eyre::Result<CoseSign1>;

    async fn create_nonce(&mut self) -> eyre::Result<Nonce>;

    fn verify_cose_singature(sign: &CoseSign1, pub_key: &PublicKey) -> eyre::Result<()> {
        let alg = sign
            .protected
            .header
            .alg
            .as_ref()
            .and_then(|alg| match alg {
                coset::RegisteredLabelWithPrivate::Assigned(alg) => Some(alg),
                coset::RegisteredLabelWithPrivate::PrivateUse(_)
                | coset::RegisteredLabelWithPrivate::Text(_) => None,
            })
            .ok_or_eyre("missing alg header")?;

        debug!(
            pub_key = ?pub_key.pk_type,
            algo = ?alg,
            "checking algorithm and public key"
        );

        let key = pub_key.key();
        let key = match (pub_key.pk_type, alg) {
            (PkType::Secp256R1, coset::iana::Algorithm::ES256) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
                    key,
                )
            }
            (PkType::Secp384R1, coset::iana::Algorithm::ES384) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED,
                    key,
                )
            }
            (PkType::Rsa2048Restr, coset::iana::Algorithm::RS256)
            | (PkType::RsaPkcs, coset::iana::Algorithm::RS256) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
                    key,
                )
            }
            (PkType::RsaPkcs, coset::iana::Algorithm::RS384) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::RSA_PKCS1_3072_8192_SHA384,
                    key,
                )
            }
            (PkType::RsaPss, coset::iana::Algorithm::RS256) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::RSA_PSS_2048_8192_SHA256,
                    key,
                )
            }
            (PkType::RsaPss, coset::iana::Algorithm::RS384) => {
                aws_lc_rs::signature::UnparsedPublicKey::new(
                    &aws_lc_rs::signature::RSA_PSS_2048_8192_SHA384,
                    key,
                )
            }
            _ => bail!("unsupported or invalid cose signing algorithm and public key pair"),
        };

        sign.verify_signature(&[], |signature, message| key.verify(message, signature))?;

        Ok(())
    }

    fn verify_hash(to_check: &Hash<'_>, data: &[u8]) -> eyre::Result<()> {
        let alg = match to_check.hashtype {
            Hashtype::Sha256 => &aws_lc_rs::digest::SHA256,
            Hashtype::Sha384 => &aws_lc_rs::digest::SHA384,
            Hashtype::HmacSha256 | Hashtype::HmacSha384 => bail!("hmac type instead of hash"),
        };

        let digest = aws_lc_rs::digest::digest(alg, data);

        if to_check.hash.as_ref() != digest.as_ref() {
            bail!("hash mismatch");
        }

        Ok(())
    }

    type KeyExchange;

    /// Used in the key exchange.
    ///
    /// This should return an ephemeral key for the communication with the owner.
    async fn key_exchange(
        &mut self,
        ow_key: &XAKeyExchange,
    ) -> eyre::Result<(XBKeyExchange<'static>, Self::KeyExchange)>;

    fn cose_decrypt(enc: &CoseEncrypt0, key: &Self::KeyExchange) -> eyre::Result<Vec<u8>>;

    fn cose_encrypt(
        &mut self,
        key: &Self::KeyExchange,
        payload: &[u8],
    ) -> eyre::Result<CoseEncrypt0>;
}
