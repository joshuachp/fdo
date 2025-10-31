use std::borrow::Cow;
use std::io::Write;

use aws_lc_rs::aead::{Aad, RandomizedNonceKey};
use aws_lc_rs::agreement;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair};
use coset::iana::Algorithm as CoseAlgorithm;
use coset::{CoseEncrypt0, CoseSign1, CoseSign1Builder, HeaderBuilder};
use eyre::{Context, OptionExt, bail, ensure, eyre};
use rcgen::{CertificateParams, DistinguishedName, DnType};
use serde_bytes::ByteBuf;
use tracing::debug;
use zeroize::Zeroizing;

use crate::crypto::kdf;
use crate::protocol::v101::Nonce;
use crate::protocol::v101::hash_hmac::{HMac, Hashtype};
use crate::protocol::v101::key_exchange::{KexSuitNames, XAKeyExchange, XBKeyExchange};
use crate::protocol::v101::public_key::{PkEnc, PkType};
use crate::protocol::v101::sign_info::DeviceSgType;
use crate::storage::Storage;

use super::Crypto;

const AES_256_KEY_FILE: &str = "aes-256-key.bin";
const PRIVATE_ECC_KEY_FILE: &str = "private-key.ecc.p8";

pub(crate) struct SoftwareCrypto<S> {
    rng: SystemRandom,
    storage: S,
}

impl<S> SoftwareCrypto<S> {
    pub(crate) async fn create(storage: S) -> eyre::Result<Self>
    where
        S: Storage,
    {
        let rand = SystemRandom::new();

        let this = Self { rng: rand, storage };

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

        self.rng.fill(key.as_mut_slice())?;

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
        let key = EcdsaKeyPair::generate_pkcs8(Self::alg(), &self.rng)?;

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
            bail!("invalid cose algorithm")
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

                    let len = key.open_in_place(nonce, aad, &mut ciphertext)?.len();
                    ciphertext.resize(len, 0);

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

    fn sign_info_type(&self) -> DeviceSgType {
        DeviceSgType::StSecP256R1
    }

    fn kex_suit(&mut self) -> KexSuitNames {
        KexSuitNames::ECDH256
    }

    fn cipher_suite(&mut self) -> CoseAlgorithm {
        CoseAlgorithm::A256GCM
    }

    async fn csr(&mut self, device_info: &str) -> eyre::Result<Vec<u8>> {
        // The device info for the certificate
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, device_info);

        let mut csr_param = CertificateParams::new([])?;
        csr_param.distinguished_name = dn;

        let key = self.signing_key().await?;

        let compat = RcgenKeyCompat::new(&key, &self.rng);

        // Singed CSR
        let csr = csr_param.serialize_request(&compat)?;

        Ok(csr.der().to_vec())
    }

    async fn hmac_secret(&mut self) -> eyre::Result<coset::CoseEncrypt0>
    where
        S: Storage,
    {
        let mut hmac_secret = Zeroizing::new(vec![0; aws_lc_rs::digest::SHA256_OUTPUT_LEN]);

        self.rng.fill(hmac_secret.as_mut_slice())?;

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
            hashtype: Hashtype::HmacSha256,
            hash: Cow::Owned(ByteBuf::from(tag.as_ref())),
        })
    }

    async fn verify_hmac(
        &mut self,
        ec_secret: &CoseEncrypt0,
        hmac: &HMac<'_>,
        data: &[u8],
    ) -> eyre::Result<()> {
        let sec = self.decrypt_cose(ec_secret).await?;

        if hmac.hashtype != Hashtype::HmacSha256 {
            bail!("invalid hmac algorithm");
        }

        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &sec);

        aws_lc_rs::hmac::verify(&key, data, &hmac.hash).wrap_err("couldn't verify hmac")
    }

    async fn cose_sing(
        &mut self,
        unprotected: HeaderBuilder,
        payload: Vec<u8>,
    ) -> eyre::Result<CoseSign1> {
        let Some(bytes) = self.storage.read(PRIVATE_ECC_KEY_FILE).await? else {
            bail!("missing private key");
        };

        let bytes = Zeroizing::new(bytes);

        let key = EcdsaKeyPair::from_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &bytes,
        )?;

        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .build();

        let unprotected = unprotected.build();

        let eat = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .try_create_signature(&[], |bytes| -> eyre::Result<Vec<u8>> {
                let sign = key.sign(&self.rng, bytes)?;

                Ok(sign.as_ref().to_vec())
            })?
            .build();

        let peer_public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED,
            key.public_key().as_ref(),
        );

        eat.verify_signature(&[], |sign, data| peer_public_key.verify(data, sign))
            .unwrap();

        Ok(eat)
    }

    async fn create_nonce(&mut self) -> eyre::Result<Nonce> {
        let mut nonce = Nonce::default();

        self.rng.fill(nonce.as_mut_slice())?;

        Ok(nonce)
    }

    type KeyExchange = Zeroizing<[u8; 32]>;

    // TODO: support different keys?
    async fn key_exchange(
        &mut self,
        ow_key: &XAKeyExchange<'_>,
    ) -> eyre::Result<(XBKeyExchange<'static>, Self::KeyExchange)> {
        let dv_priv_key =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &self.rng)?;

        // 128 bits for ECDH256
        let mut dv_rand = [0u8; 16];
        self.rng.fill(dv_rand.as_mut_slice())?;

        let dv_pub_key = dv_priv_key.compute_public_key()?;

        let (bx, by) = parse_ecc_params(dv_pub_key.as_ref())?;

        let xb_key_exchange = XBKeyExchange::create(bx, by, &dv_rand)?;

        let (ax, ay, ov_rand) = ow_key.parse_ecdh()?;

        debug!(ax = ax.len(), ay = ay.len());

        ensure!((ax.len(), ay.len()) == (32, 32), "mismatched point lenght");

        let mut ov_pub_key = [0; 1 + 32 + 32];
        let mut cursor = std::io::Cursor::new(ov_pub_key.as_mut_slice());
        cursor.write(&[0x4])?;
        cursor.write(ax)?;
        cursor.write(ay)?;

        let ow_pub_key = aws_lc_rs::agreement::UnparsedPublicKey::new(
            &aws_lc_rs::agreement::ECDH_P256,
            ov_pub_key,
        );

        let key = aws_lc_rs::agreement::agree_ephemeral(
            dv_priv_key,
            &ow_pub_key,
            eyre!("failed key agreement"),
            |sh_x: &[u8]| {
                // create key
                let len = sh_x
                    .len()
                    .checked_add(dv_rand.len())
                    .and_then(|len| len.checked_add(ov_rand.len()))
                    .ok_or_eyre("len overflow")?;

                let mut sh_se = Zeroizing::new(vec![0u8; len]);

                let mut cursor = std::io::Cursor::new(sh_se.as_mut_slice());

                cursor.write(&sh_x)?;
                cursor.write(dv_rand.as_slice())?;
                cursor.write(&ov_rand)?;

                const LABEL: &[u8; 8] = b"FIDO-KDF";
                // Context rand is "" for ECDH256
                const CONTEXT: &[u8; 22] = b"AutomaticOnboardTunnel";

                const OUTPUT_LEN: usize = 32;

                let mut output_key = [0u8; OUTPUT_LEN];

                kdf::kdf::<1, 2, OUTPUT_LEN>(
                    aws_lc_rs::hmac::HMAC_SHA256,
                    &sh_se,
                    LABEL,
                    CONTEXT,
                    &mut output_key,
                )?;

                let output_key = Zeroizing::new(output_key);

                Ok(output_key)
            },
        )?;

        Ok((xb_key_exchange, key))
    }

    fn cose_decrypt(enc: &CoseEncrypt0, key: &Self::KeyExchange) -> eyre::Result<Vec<u8>> {
        let alg = enc
            .protected
            .header
            .alg
            .as_ref()
            .ok_or_eyre("mising alg header in cose object")?;

        debug!(?alg);

        if *alg != coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::A256GCM) {
            bail!("invalid cose algorithm")
        }

        let key = RandomizedNonceKey::new(&aws_lc_rs::aead::AES_256_GCM, key.as_slice())?;
        debug!("key created");

        let nonce = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&enc.unprotected.iv)?;
        debug!("nonce created");

        enc.decrypt_ciphertext(
            &[],
            || eyre!("missing cypher text"),
            |ciphertext, aad| {
                let aad = Aad::from(aad);
                let mut in_out = Vec::from(ciphertext);

                let len = key
                    .open_in_place(nonce, aad, &mut in_out)
                    .wrap_err("couldn't decrypt message")?
                    .len();

                // remove the length
                in_out.resize(len, 0);

                Ok(in_out)
            },
        )
    }

    fn cose_encrypt(
        &mut self,
        key: &Self::KeyExchange,
        payload: &[u8],
    ) -> eyre::Result<CoseEncrypt0> {
        let key = RandomizedNonceKey::new(&aws_lc_rs::aead::AES_256_GCM, key.as_slice())?;

        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::A256GCM)
            .build();

        let mut nonce = None;

        let builder = coset::CoseEncrypt0Builder::new()
            .protected(protected)
            .try_create_ciphertext(&payload, &[], |plain, aad| -> eyre::Result<Vec<u8>> {
                let mut in_out = Vec::from(plain);

                nonce = Some(key.seal_in_place_append_tag(Aad::from(aad), &mut in_out)?);

                Ok(in_out)
            })?;

        let nonce = nonce.ok_or_eyre("nonce not created")?;

        let unprotected = coset::HeaderBuilder::new()
            .iv(nonce.as_ref().to_vec())
            .build();

        let enc = builder.unprotected(unprotected).build();

        Ok(enc)
    }
}

fn parse_ecc_params(buf: &[u8]) -> eyre::Result<(&[u8], &[u8])> {
    ensure!(buf.len() == 65, "key was {}", buf.len());
    ensure!(buf[0] == 0x4, "first byte was {}", buf[0]);

    Ok(buf[1..].split_at(32))
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
