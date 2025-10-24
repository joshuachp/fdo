use std::str::FromStr;

use bitflags::bitflags;
use eyre::{OptionExt, bail, eyre};
use tracing::{debug, info, warn};
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::{AlgorithmIdentifier, CapabilityType};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    CapabilityData, CreatePrimaryKeyResult, PcrSelectionList, PcrSlot, PublicBuilder,
    SymmetricCipherParameters, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;

pub(crate) struct TpmCrypto {
    ctx: Context,
    key: CreatePrimaryKeyResult,
}

impl TpmCrypto {
    pub(crate) fn create(tpm_connection: Option<String>, pcrs: Vec<u8>) -> eyre::Result<Self> {
        let tpm_connection = tpm_connection.as_deref().unwrap_or("device:/dev/tpmrm0");

        let conf = TctiNameConf::from_str(tpm_connection)?;
        let mut ctx = Context::new(conf)?;

        info!(tpm_connection, "connected to tpm");

        //let caps = Self::read_caps(&mut ctx)?;
        // info!(?caps, "capabilities gathered");

        let pcrs = Self::pcr_slots(pcrs)?;
        let key = Self::create_primary(&mut ctx, pcrs)?;

        Ok(Self { ctx, key })
    }

    fn pcr_slots(pcrs: Vec<u8>) -> eyre::Result<Vec<PcrSlot>> {
        pcrs.into_iter()
            .map(|value| {
                let pcr = match value {
                    0 => PcrSlot::Slot0,
                    1 => PcrSlot::Slot1,
                    2 => PcrSlot::Slot2,
                    3 => PcrSlot::Slot3,
                    4 => PcrSlot::Slot4,
                    5 => PcrSlot::Slot5,
                    6 => PcrSlot::Slot6,
                    7 => PcrSlot::Slot7,
                    8 => PcrSlot::Slot8,
                    9 => PcrSlot::Slot9,
                    10 => PcrSlot::Slot10,
                    11 => PcrSlot::Slot11,
                    12 => PcrSlot::Slot12,
                    13 => PcrSlot::Slot13,
                    14 => PcrSlot::Slot14,
                    15 => PcrSlot::Slot15,
                    16 => PcrSlot::Slot16,
                    17 => PcrSlot::Slot17,
                    18 => PcrSlot::Slot18,
                    19 => PcrSlot::Slot19,
                    20 => PcrSlot::Slot20,
                    21 => PcrSlot::Slot21,
                    22 => PcrSlot::Slot22,
                    23 => PcrSlot::Slot23,
                    24 => PcrSlot::Slot24,
                    25 => PcrSlot::Slot25,
                    26 => PcrSlot::Slot26,
                    27 => PcrSlot::Slot27,
                    28 => PcrSlot::Slot28,
                    29 => PcrSlot::Slot29,
                    30 => PcrSlot::Slot30,
                    31 => PcrSlot::Slot31,
                    _ => return Err(eyre!("invalid slot {value}")),
                };

                Ok(pcr)
            })
            .collect()
    }

    fn create_primary(
        ctx: &mut Context,
        pcrs: Vec<PcrSlot>,
    ) -> eyre::Result<CreatePrimaryKeyResult> {
        // These other objects are encrypted by the primary key allowing them to persist
        // over a reboot and reloads.
        //
        // A primary key is derived from a seed, and provided that the same inputs are given
        // the same primary key will be derived in the tpm. This means that you do not need
        // to store or save the details of this key - only the parameters of how it was created.

        let object_attributes = ObjectAttributesBuilder::new()
            // Indicate the key can only exist within this tpm and can not be exported.
            .with_fixed_tpm(true)
            // The primary key and it's descendent keys can't be moved to other primary
            // keys.
            .with_fixed_parent(true)
            // The primary key will persist over suspend and resume of the system.
            .with_st_clear(false)
            // The primary key was generated entirely inside the TPM - only this TPM
            // knows it's content.
            .with_sensitive_data_origin(true)
            // This key requires "authentication" to the TPM to access - this can be
            // an HMAC or password session. HMAC sessions are used by default with
            // the "execute_with_nullauth_session" function.
            .with_user_with_auth(true)
            // This key has the ability to decrypt
            .with_decrypt(true)
            // This key may only be used to encrypt or sign objects that are within
            // the TPM - it can not encrypt or sign external data.
            .with_restricted(true)
            .build()?;

        let primary_pub = PublicBuilder::new()
            // This key is a symmetric key.
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
                SymmetricDefinitionObject::AES_256_CFB,
            ))
            .with_symmetric_cipher_unique_identifier(tss_esapi::structures::Digest::default())
            .build()?;

        let pcrs = PcrSelectionList::builder()
            .with_selection(HashingAlgorithm::Sha256, &pcrs)
            .build()?;

        let primary = ctx.execute_with_nullauth_session(|ctx| {
            // Create the key under the "owner" hierarchy. Other hierarchies are platform
            // which is for boot services, null which is ephemeral and resets after a reboot,
            // and endorsement which allows key certification by the TPM manufacturer.
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, Some(pcrs))
        })?;

        info!("create primary key handle");

        Ok(primary)
    }

    fn _read_caps(ctx: &mut Context) -> eyre::Result<Capabilities> {
        let mut hash = HashBitSet::empty();
        let mut aes = false;
        let mut eccdsa = false;
        let mut hmac = false;

        let mut property = 0;
        loop {
            let (cap, more) = ctx.get_capability(CapabilityType::Algorithms, property, 10)?;

            match cap {
                CapabilityData::Algorithms(list) => {
                    for alg in list {
                        debug!(alg = ?alg.algorithm_identifier(), prop = ?alg.algorithm_properties(), "algo cap");

                        let idtf = alg.algorithm_identifier();
                        let props = alg.algorithm_properties();

                        if props.hash() {
                            hash |= HashBitSet::from(idtf);
                        }

                        if props.hash() && props.signing() {
                            hmac |= idtf == AlgorithmIdentifier::Hmac
                        }

                        if props.symmetric() {
                            aes |= idtf == AlgorithmIdentifier::Aes;
                        }

                        if props.asymmetric() && props.signing() {
                            eccdsa |= idtf == AlgorithmIdentifier::EcDsa;
                        }

                        property = u32::from(u16::from(idtf))
                            .checked_add(1)
                            .ok_or_eyre("property overflow")?;
                    }
                }
                _ => {
                    warn!(?cap, "skipping of wrong group")
                }
            }

            if !more {
                break;
            }

            debug!("itereting next property");
        }

        let hash = if hash.contains(HashBitSet::SHA256) {
            HashingAlgorithm::Sha256
        } else if hash.contains(HashBitSet::SHA512) {
            HashingAlgorithm::Sha512
        } else if hash.contains(HashBitSet::SHA384) {
            HashingAlgorithm::Sha384
        } else {
            bail!("TPM doesn't support a viable hashing algorithm");
        };

        // TODO: consider more algorithms
        if !aes {
            bail!("TPM doesn't support AES symmetric encryption");
        }

        if !eccdsa {
            bail!("TPM doesn't support ECDSA signing");
        }

        if !hmac {
            bail!("TPM doesn't support HMAC digest signing");
        }

        Ok(Capabilities { hash })
    }
}

bitflags! {
    struct HashBitSet: u8 {
        const SHA256 = 0b0001;
        const SHA384 = 0b0010;
        const SHA512 = 0b0100;
    }
}

impl From<AlgorithmIdentifier> for HashBitSet {
    fn from(value: AlgorithmIdentifier) -> Self {
        match value {
            AlgorithmIdentifier::Sha256 => HashBitSet::SHA256,
            AlgorithmIdentifier::Sha384 => HashBitSet::SHA384,
            AlgorithmIdentifier::Sha512 => HashBitSet::SHA512,
            _ => HashBitSet::empty(),
        }
    }
}

#[derive(Debug)]
struct Capabilities {
    hash: HashingAlgorithm,
}
