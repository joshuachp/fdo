use std::borrow::Cow;

use aws_lc_rs::aead::{Aad, RandomizedNonceKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair};
use eyre::{OptionExt, bail, eyre};
use rcgen::{CertificateParams, DistinguishedName, DnType};
use serde_bytes::ByteBuf;
use zeroize::Zeroizing;

use crate::protocol::v101::hash_hmac::{HMac, Hash, Hashtype};
use crate::protocol::v101::public_key::{PkEnc, PkType};
use crate::storage::Storage;

use super::Crypto;

const AES_256_KEY_FILE: &str = "aes-256-key.bin";
const PRIVATE_ECC_KEY_FILE: &str = "private-key.ecc.p8";

pub(crate) struct SoftwareCrypto<S> {
    rand: SystemRandom,
    storage: S,
}

impl<S> SoftwareCrypto<S> {
    pub(crate) async fn create(storage: S) -> eyre::Result<Self>
    where
        S: Storage,
    {
        let rand = SystemRandom::new();

        let this = Self { rand, storage };

        if !this.storage.exists(AES_256_KEY_FILE).await? {
            this.create_aes_key().await?;
        }

        if !this.storage.exists(PRIVATE_ECC_KEY_FILE).await? {
            this.create_signing_keys().await?;
        }

        Ok(this)
    }

    fn alg() -> &'static aws_lc_rs::signature::EcdsaSigningAlgorithm {
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING
    }

    async fn create_aes_key(&self) -> eyre::Result<()>
    where
        S: Storage,
    {
        let mut key = Zeroizing::new(vec![0; aws_lc_rs::digest::SHA256_OUTPUT_LEN]);

        self.rand.fill(key.as_mut_slice())?;

        self.storage.write_immutable(AES_256_KEY_FILE, &key).await?;

        Ok(())
    }

    async fn aes_key(&self) -> eyre::Result<Zeroizing<Vec<u8>>>
    where
        S: Storage,
    {
        let key = self
            .storage
            .read_secret(AES_256_KEY_FILE)
            .await
            .and_then(|key| key.ok_or_eyre("key file misisng"))?;

        debug_assert_eq!(key.len(), 32);

        Ok(key)
    }

    async fn create_signing_keys(&self) -> eyre::Result<()>
    where
        S: Storage,
    {
        let key = EcdsaKeyPair::generate_pkcs8(Self::alg(), &self.rand)?;

        self.storage
            .write_immutable(PRIVATE_ECC_KEY_FILE, key.as_ref())
            .await?;

        Ok(())
    }

    async fn signing_key(&self) -> eyre::Result<EcdsaKeyPair>
    where
        S: Storage,
    {
        let Some(bytes) = self.storage.read(PRIVATE_ECC_KEY_FILE).await? else {
            bail!("missing private key");
        };

        let bytes = Zeroizing::new(bytes);

        let key = EcdsaKeyPair::from_pkcs8(Self::alg(), &bytes)?;

        Ok(key)
    }

    async fn decrypt_cose(
        &mut self,
        ec_secret: &coset::CoseEncrypt0,
    ) -> Result<Zeroizing<Vec<u8>>, eyre::Error>
    where
        S: Storage,
    {
        let alg = ec_secret
            .protected
            .header
            .alg
            .as_ref()
            .ok_or_eyre("mising alg header in cose object")?;

        if *alg != coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::A256GCM) {
            bail!("invalid cosealgorithm")
        }

        let aes_key = self.aes_key().await?;

        let key = RandomizedNonceKey::new(&aws_lc_rs::aead::AES_256_GCM, &aes_key)?;
        let nonce = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&ec_secret.unprotected.iv)?;

        let hmac_secret = ec_secret
            .decrypt_ciphertext(
                &[],
                || eyre!("missing cypher text"),
                |ciphertext, aad| {
                    let aad = Aad::from(aad);
                    let mut ciphertext = Vec::from(ciphertext);

                    key.open_in_place(nonce, aad, &mut ciphertext)?;

                    Ok(ciphertext)
                },
            )
            .map(Zeroizing::new)?;

        Ok(hmac_secret)
    }

    async fn encrypt_cose(
        &mut self,
        hmac_secret: Zeroizing<Vec<u8>>,
    ) -> Result<coset::CoseEncrypt0, eyre::Error>
    where
        S: Storage,
    {
        let aes_key = self.aes_key().await?;

        let key = RandomizedNonceKey::new(&aws_lc_rs::aead::AES_256_GCM, &aes_key)?;

        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::A256GCM)
            .build();

        let mut nonce = None;

        let builder = coset::CoseEncrypt0Builder::new()
            .protected(protected)
            .try_create_ciphertext(&hmac_secret, &[], |plain, aad| -> eyre::Result<Vec<u8>> {
                let mut in_out = Vec::from(plain);

                nonce = Some(key.seal_in_place_append_tag(Aad::from(aad), &mut in_out)?);

                Ok(in_out)
            })?;

        let nonce = nonce.ok_or_eyre("nonce not created")?;

        let unprotected = coset::HeaderBuilder::new()
            .iv(nonce.as_ref().to_vec())
            .build();

        let hmac_enc = builder.unprotected(unprotected).build();

        Ok(hmac_enc)
    }
}

impl<S> Crypto for SoftwareCrypto<S>
where
    S: Storage,
{
    const PK_ENC: PkEnc = PkEnc::X509;

    fn pk_type(&mut self) -> PkType {
        PkType::Secp256R1
    }

    async fn csr(&mut self, device_info: &str) -> eyre::Result<Vec<u8>> {
        // The device info for the certificate
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, device_info);

        let mut csr_param = CertificateParams::new([])?;
        csr_param.distinguished_name = dn;

        let key = self.signing_key().await?;

        let compat = RcgenKeyCompat::new(&key, &self.rand);

        // Singed CSR
        let csr = csr_param.serialize_request(&compat)?;

        Ok(csr.der().to_vec())
    }

    async fn hmac_secret(&mut self) -> eyre::Result<coset::CoseEncrypt0>
    where
        S: Storage,
    {
        let mut hmac_secret = Zeroizing::new(vec![0; aws_lc_rs::digest::SHA256_OUTPUT_LEN]);

        self.rand.fill(hmac_secret.as_mut_slice())?;

        let hmac_enc = self.encrypt_cose(hmac_secret).await?;

        Ok(hmac_enc)
    }

    async fn hmac(
        &mut self,
        ec_secret: &coset::CoseEncrypt0,
        data: &[u8],
    ) -> eyre::Result<HMac<'static>> {
        let hmac_secret = self.decrypt_cose(ec_secret).await?;

        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, hmac_secret.as_slice());

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

struct RcgenKeyCompat<'a> {
    keys: &'a EcdsaKeyPair,
    rand: &'a SystemRandom,
}

impl<'a> RcgenKeyCompat<'a> {
    fn new(keys: &'a EcdsaKeyPair, rand: &'a SystemRandom) -> Self {
        Self { keys, rand }
    }
}

impl rcgen::PublicKeyData for RcgenKeyCompat<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.keys.public_key().as_ref()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for RcgenKeyCompat<'_> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.keys
            .sign(self.rand, msg)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| rcgen::Error::RingUnspecified)
    }
}
