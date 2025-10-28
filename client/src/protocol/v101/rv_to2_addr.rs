use serde::{Deserialize, Serialize};

use crate::protocol::OneOrMore;

use super::{DnsAddress, IpAddress, Port, TransportProtocol};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RvTo2Addr<'a>(OneOrMore<RvTo2AddrEntry<'a>>);

/// ```cddl
/// RVTO2AddrEntry = [
///    RVIP: IPAddress / null,       ;; IP address where Owner is waiting for TO2
///    RVDNS: DNSAddress / null,     ;; DNS address where Owner is waiting for TO2
///    RVPort: Port,                 ;; TCP/UDP port to go with above
///    RVProtocol: TransportProtocol ;; Protocol, to go with above
/// ]
/// ```
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RvTo2AddrEntry<'a> {
    rv_ip: Option<IpAddress>,
    rv_dns: Option<DnsAddress<'a>>,
    rv_port: Port,
    rv_protocol: TransportProtocol,
}

impl Serialize for RvTo2AddrEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Self {
            rv_ip,
            rv_dns,
            rv_port,
            rv_protocol,
        } = self;

        (rv_ip, rv_dns, rv_port, rv_protocol).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RvTo2AddrEntry<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (rv_ip, rv_dns, rv_port, rv_protocol) = Deserialize::deserialize(deserializer)?;

        Ok(Self {
            rv_ip,
            rv_dns,
            rv_port,
            rv_protocol,
        })
    }
}
