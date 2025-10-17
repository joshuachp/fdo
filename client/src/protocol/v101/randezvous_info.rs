use std::fmt::Debug;

use eyre::bail;
use serde::{Deserialize, Serialize};

use crate::protocol::{CborBstr, OneOrMore};

/// ```cddl
/// RendezvousInfo = [
///     + RendezvousDirective
/// ]
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RendezvousInfo(OneOrMore<RendezvousDirective>);

/// ```cddl
/// RendezvousDirective = [
///     + RendezvousInstr
/// ]
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RendezvousDirective(OneOrMore<RendezvousInstr>);

/// ```cddl
/// RendezvousInstr = [
///     RVVariable,
///     RVValue
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RendezvousInstr {
    rv_variable: RVVariable,
    rv_value: RVValue,
}

impl Serialize for RendezvousInstr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            rv_variable,
            rv_value,
        } = self;

        (rv_variable, rv_value).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RendezvousInstr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (rv_variable, rv_value) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            rv_variable,
            rv_value,
        })
    }
}

/// ```cddl
/// RVVariable = uint8
/// $RVVariable = ()
/// RVVariable /= (
///     RVDevOnly     => 0,
///     RVOwnerOnly   => 1,
///     RVIPAddress   => 2,
///     RVDevPort     => 3,
///     RVOwnerPort   => 4,
///     RVDns         => 5,
///     RVSvCertHash  => 6,
///     RVClCertHash  => 7,
///     RVUserInput   => 8,
///     RVWifiSsid    => 9,
///     RVWifiPw      => 10,
///     RVMedium      => 11,
///     RVProtocol    => 12,
///     RVDelaysec    => 13,
///     RVBypass      => 14,
///     RVExtRV       => 15
/// )
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
#[repr(u8)]
pub(crate) enum RVVariable {
    RVDevOnly = 0,
    RVOwnerOnly = 1,
    RVIPAddress = 2,
    RVDevPort = 3,
    RVOwnerPort = 4,
    RVDns = 5,
    RVSvCertHash = 6,
    RVClCertHash = 7,
    RVUserInput = 8,
    RVWifiSsid = 9,
    RVWifiPw = 10,
    RVMedium = 11,
    RVProtocol = 12,
    RVDelaysec = 13,
    RVBypass = 14,
    RVExtRV = 15,
}

impl Debug for RVVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RVDevOnly => write!(f, "RVDevOnly(0)"),
            Self::RVOwnerOnly => write!(f, "RVOwnerOnly(1)"),
            Self::RVIPAddress => write!(f, "RVIPAddress(2)"),
            Self::RVDevPort => write!(f, "RVDevPort(3)"),
            Self::RVOwnerPort => write!(f, "RVOwnerPort(4)"),
            Self::RVDns => write!(f, "RVDns(5)"),
            Self::RVSvCertHash => write!(f, "RVSvCertHash(6)"),
            Self::RVClCertHash => write!(f, "RVClCertHash(7)"),
            Self::RVUserInput => write!(f, "RVUserInput(8)"),
            Self::RVWifiSsid => write!(f, "RVWifiSsid(9)"),
            Self::RVWifiPw => write!(f, "RVWifiPw(10)"),
            Self::RVMedium => write!(f, "RVMedium(11)"),
            Self::RVProtocol => write!(f, "RVProtocol(12)"),
            Self::RVDelaysec => write!(f, "RVDelaysec(13)"),
            Self::RVBypass => write!(f, "RVBypass(14)"),
            Self::RVExtRV => write!(f, "RVExtRV(15)"),
        }
    }
}

impl TryFrom<u8> for RVVariable {
    type Error = eyre::Report;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let value = match value {
            0 => Self::RVDevOnly,
            1 => Self::RVOwnerOnly,
            2 => Self::RVIPAddress,
            3 => Self::RVDevPort,
            4 => Self::RVOwnerPort,
            5 => Self::RVDns,
            6 => Self::RVSvCertHash,
            7 => Self::RVClCertHash,
            8 => Self::RVUserInput,
            9 => Self::RVWifiSsid,
            10 => Self::RVWifiPw,
            11 => Self::RVMedium,
            12 => Self::RVProtocol,
            13 => Self::RVDelaysec,
            14 => Self::RVBypass,
            15 => Self::RVExtRV,
            _ => bail!("value out of range: {value}"),
        };

        Ok(value)
    }
}

impl From<RVVariable> for u8 {
    fn from(value: RVVariable) -> Self {
        value as u8
    }
}

// RVProtocolValue /= (
//     RVProtRest    => 0,
//     RVProtHttp    => 1,
//     RVProtHttps   => 2,
//     RVProtTcp     => 3,
//     RVProtTls     => 4,
//     RVProtCoapTcp => 5,
//     RVProtCoapUdp => 6
// );
// $RVMediumValue /= (
// )

/// ```cddl
/// RVValue = bstr .cbor any
/// ```
pub(crate) type RVValue = CborBstr<ciborium::Value>;
