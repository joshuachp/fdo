use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_bytes::Bytes;

use super::Protver;
use super::guid::Guid;
use super::hash_hmac::Hash;
use super::randezvous_info::RendezvousInfo;

/// Persisted device credentials after DI.
///
/// The stored DCGuid, DCRVInfo and DCPubKeyHash fields are updated during the TO2 protocol. See
/// TO2.SetupDevice for details. These fields must be stored in a non-volatile, mutable storage
/// medium.
///
/// ```cddl
/// DeviceCredential = [
///     DCActive:     bool,
///     DCProtVer:    protver,
///     DCHmacSecret: bstr,           ;; confidentiality required
///     DCDeviceInfo: tstr,
///     DCGuid:       Guid,           ;; modified in TO2
///     DCRVInfo:     RendezvousInfo, ;; modified in TO2
///     DCPubKeyHash: Hash            ;; modified in TO2
/// ]
///
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DeviceCredential<'a> {
    /// Indicates whether FIDO Device Onboard is active.
    ///
    /// When a device is manufactured, this field is initialized to True, indicating that FIDO
    /// Device Onboard must start when the device is powered on. When the TO2 protocol is
    /// successful, this field is set to False, indicating that FIDO Device Onboard should remain
    /// dormant.
    pub(crate) dc_active: bool,
    /// Specifies the protocol version.
    pub(crate) dc_prot_ver: Protver,
    /// Contains a secret.
    ///
    /// Initialized with a random value by the Device during the DI protocol or equivalent Device
    /// initialization.
    ///
    /// Requires confidentiality.
    pub(crate) dc_hmac_secret: Cow<'a, Bytes>,
    /// Device information.
    ///
    /// Is a text string that is used by the manufacturer to indicate the device type, sufficient to
    /// allow an onboarding procedure or script to be selected by the Owner.
    pub(crate) dc_device_info: Cow<'a, str>,
    /// Current device’s GUID.
    ///
    /// To be used for the next ownership transfer.
    ///
    /// Modified in TO2
    pub(crate) dc_guid: Guid,
    /// Contains instructions on how to find the Secure Device Onboard Rendezvous Server.
    ///
    /// Modified in TO2
    pub(crate) dc_rv_info: RendezvousInfo,
    /// Is a hash of the manufacturer’s public key, which must match the hash of OwnershipVoucher.OVHeader.OVPubKey
    ///
    /// Modified in TO2
    pub(crate) dc_pub_key_hash: Hash<'a>,
}
