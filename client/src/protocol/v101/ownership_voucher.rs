use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::protocol::CborBstr;

use super::Protver;
use super::guid::Guid;
use super::hash_hmac::HMac;
use super::public_key::PublicKey;
use super::randezvous_info::RendezvousInfo;

/// Ownership Voucher top level structure
///
/// ```cddl
/// OwnershipVoucher = [
///     OVProtVer:      protver,           ;; protocol version
///     OVHeaderTag:    bstr .cbor OVHeader,
///     OVHeaderHMac:   HMac,              ;; hmac[DCHmacSecret, OVHeader]
///     OVDevCertChain: OVDevCertChainOrNull,
///     OVEntryArray:   OVEntries
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OwnershipVoucher<'a> {
    ov_prot_ver: Protver,
    ov_header_tag: CborBstr<OvHeader<'a>>,
    ov_header_hmac: HMac<'a>,
    ov_dev_cert_chain: OvDevCertChainHashOrNull<'a>,
    // TODO change
    ov_entry_array: ciborium::Value,
}

impl Serialize for OwnershipVoucher<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            ov_prot_ver,
            ov_header_tag,
            ov_header_hmac,
            ov_dev_cert_chain,
            ov_entry_array,
        } = self;

        (
            ov_prot_ver,
            ov_header_tag,
            ov_header_hmac,
            ov_dev_cert_chain,
            ov_entry_array,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OwnershipVoucher<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (ov_prot_ver, ov_header_tag, ov_header_hmac, ov_dev_cert_chain, ov_entry_array) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            ov_prot_ver,
            ov_header_tag,
            ov_header_hmac,
            ov_dev_cert_chain,
            ov_entry_array,
        })
    }
}

/// ;; Ownership Voucher header, also used in TO1 protocol
/// OVHeader = [
///     OVHProtVer:        protver,        ;; protocol version
///     OVGuid:            Guid,           ;; guid
///     OVRVInfo:          RendezvousInfo, ;; rendezvous instructions
///     OVDeviceInfo:      tstr,           ;; DeviceInfo
///     OVPubKey:          PublicKey,      ;; mfg public key
///     OVDevCertChainHash:OVDevCertChainHashOrNull
/// ]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OvHeader<'a> {
    pub(crate) ovh_prot_ver: Protver,
    pub(crate) ov_guid: Guid,
    pub(crate) ov_rv_info: RendezvousInfo,
    pub(crate) ov_device_info: Cow<'a, str>,
    pub(crate) ov_pub_key: PublicKey<'a>,
    pub(crate) ov_dev_cert_chain_hash: OvDevCertChainHashOrNull<'a>,
}

impl Serialize for OvHeader<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            ovh_prot_ver,
            ov_guid,
            ov_rv_info,
            ov_device_info,
            ov_pub_key,
            ov_dev_cert_chain_hash,
        } = self;

        (
            ovh_prot_ver,
            ov_guid,
            ov_rv_info,
            ov_device_info,
            ov_pub_key,
            ov_dev_cert_chain_hash,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OvHeader<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (ovh_prot_ver, ov_guid, ov_rv_info, ov_device_info, ov_pub_key, ov_dev_cert_chain_hash) =
            Deserialize::deserialize(deserializer)?;

        Ok(Self {
            ovh_prot_ver,
            ov_guid,
            ov_rv_info,
            ov_device_info,
            ov_pub_key,
            ov_dev_cert_chain_hash,
        })
    }
}

// ;; Device certificate chain
// ;; use null for Intel® EPID.
// OVDevCertChainOrNull     = X5CHAIN / null  ;; CBOR null for Intel® EPID device key
// TODO: not specified
pub(crate) type OvDevCertChainHashOrNull<'a> = Option<ciborium::Value>;

//;; Hash of Device certificate chain
//;; use null for Intel® EPID
//OVDevCertChainHashOrNull = Hash / null       ;; CBOR null for Intel® EPID device key
//
//;; Ownership voucher entries array
//OVEntries = [ * OVEntry ]
//
//;; ...each entry is a COSE Sign1 object with a payload
//OVEntry = CoseSignature
//$COSEProtectedHeaders //= (
//    1: OVSignType
//)
//$COSEPayloads /= (
//    OVEntryPayload
//)
// ;; ... each payload contains the hash of the previous entry
// ;; and the signature of the public key to verify the next signature
// ;; (or the Owner, in the last entry).
// OVEntryPayload = [
//     OVEHashPrevEntry: Hash,
//     OVEHashHdrInfo:   Hash,  ;; hash[GUID||DeviceInfo] in header
//     OVEExtra:         null / bstr .cbor OVEExtraInfo
//     OVEPubKey:        PublicKey
// ]
//
// OVEExtraInfo = { * OVEExtraInfoType: bstr }
// OVEExtraInfoType = int
//
// ;;OVSignType = Supporting COSE signature types
