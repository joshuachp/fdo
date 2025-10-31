use std::borrow::Cow;
use std::net::IpAddr;
use std::time::Duration;

use coset::HeaderBuilder;
use eyre::{OptionExt, bail, eyre};
use serde_bytes::ByteBuf;
use tracing::{debug, error, info, warn};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::Ctx;
use crate::client::Client;
use crate::crypto::Crypto;
use crate::protocol::v101::device_credentials::DeviceCredential;
use crate::protocol::v101::eat_signature::{EAT_NONCE, EAT_UEID};
use crate::protocol::v101::sign_info::SigInfo;
use crate::protocol::v101::to1::hello_rv::HelloRv;
use crate::protocol::v101::to1::prove_to_rv::ProveToRv;
use crate::protocol::v101::{DnsAddress, IpAddress};
use crate::storage::Storage;

use super::v101::hash_hmac::Hash;
use super::v101::randezvous_info::{
    RVVariable, RendezvousDirective, RvMediumValue, RvProtocolValue,
};
use super::v101::sign_info::EASigInfo;
use super::v101::to1::hello_rv_ack::HelloRvAck;
use super::v101::to1::rv_redirect::RvRedirect;
use super::v101::{NonceTo1Proof, Port};

/// From spec example
const DEFAULT_DELAY: Duration = Duration::from_secs(120);

macro_rules! replace_opt {
    ($this:ident, $field:ident, $value:expr) => {
        if $this.$field.replace($value).is_some() {
            bail!(concat!(stringify!($field), " was overwritten"));
        }
    };
}

// TODO missing imple https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html#rendezvous-bypass
#[derive(Debug, Default)]
struct RvDevBuilder<'a> {
    ip: Option<IpAddr>,
    dns: Option<DnsAddress<'a>>,
    port: Option<Port>,
    tls_server_cert_hash: Option<Hash<'a>>,
    tls_ca_cert_hash: Option<Hash<'a>>,
    user_input: Option<bool>,
    wifi_ssid: Option<Cow<'a, str>>,
    wifi_passwd: Option<zeroize::Zeroizing<String>>,
    medium: Option<RvMediumValue>,
    protocol: Option<RvProtocolValue>,
    delay: Option<Duration>,
    // TODO: implement this
    // bypass: Option<Bypass>,
    // external_rv: Option<Bypass>,
}

impl RvDevBuilder<'_> {
    fn try_from(value: &RendezvousDirective<'_>) -> eyre::Result<Option<Self>> {
        let mut this = RvDevBuilder::default();

        for instr in value.iter() {
            match instr.rv_variable {
                RVVariable::RVDevOnly => {
                    debug!("device only instruction");
                }
                RVVariable::RVOwnerOnly => {
                    debug!("owner instruction skipping");

                    return Ok(None);
                }
                RVVariable::RVIPAddress => {
                    let ip: IpAddress =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    let ip = ip.into();

                    replace_opt!(this, ip, ip);
                }
                RVVariable::RVDevPort => {
                    let port: u16 =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    replace_opt!(this, port, port);
                }
                RVVariable::RVOwnerPort => {
                    debug!("skipping owner port");
                }
                RVVariable::RVDns => {
                    let dns: DnsAddress =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    replace_opt!(this, dns, dns);
                }
                RVVariable::RVSvCertHash => {
                    let hash: Hash =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    replace_opt!(this, tls_server_cert_hash, hash);
                }
                RVVariable::RVClCertHash => {
                    let hash: Hash =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    replace_opt!(this, tls_ca_cert_hash, hash);
                }
                RVVariable::RVUserInput => {
                    let input: bool =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    replace_opt!(this, user_input, input);
                }
                RVVariable::RVWifiSsid => {
                    let ssid: Cow<'_, str> =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    replace_opt!(this, wifi_ssid, ssid);
                }
                RVVariable::RVWifiPw => {
                    let pw: String =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    let pw = Zeroizing::new(pw);

                    replace_opt!(this, wifi_passwd, pw);
                }
                RVVariable::RVMedium => {
                    let medium: RvMediumValue =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    replace_opt!(this, medium, medium);
                }
                RVVariable::RVProtocol => {
                    let proto: RvProtocolValue =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    replace_opt!(this, protocol, proto);
                }
                RVVariable::RVDelaysec => {
                    let delay: u32 =
                        ciborium::from_reader(std::io::Cursor::new(instr.rv_value.as_ref()))?;

                    let delay = Duration::from_secs(delay.into());

                    replace_opt!(this, delay, delay);
                }
                RVVariable::RVBypass | RVVariable::RVExtRV => {
                    // TODO
                    warn!("rv bypass not implemented");

                    return Ok(None);
                }
            }
        }

        Ok(Some(this))
    }

    fn protocol(&self) -> RvProtocolValue {
        self.protocol.unwrap_or(RvProtocolValue::Tls)
    }

    fn delay(&self) -> Duration {
        self.delay.unwrap_or(DEFAULT_DELAY)
    }

    fn http_urls(&self) -> eyre::Result<Vec<Url>> {
        let port = self.port.unwrap_or(80);

        self.get_urls("http", port)
    }

    fn https_urls(&self) -> eyre::Result<Vec<Url>> {
        let port = self.port.unwrap_or(443);

        self.get_urls("https", port)
    }

    fn get_urls(&self, scheme: &'static str, port: u16) -> Result<Vec<Url>, eyre::Error> {
        if self.dns.is_none() && self.ip.is_none() {
            bail!("address is unset");
        }

        let mut addrs = Vec::with_capacity(2);

        if let Some(dns) = &self.dns {
            let host = Host::Domain(dns);

            let url = Url::parse(&format!("{scheme}://{host}:{port}"))?;

            addrs.push(url);
        }

        if let Some(ip) = &self.ip {
            let host: Host<String> = match ip {
                IpAddr::V4(ipv4_addr) => Host::Ipv4(*ipv4_addr),
                IpAddr::V6(ipv6_addr) => Host::Ipv6(*ipv6_addr),
            };

            let url = Url::parse(&format!("{scheme}://{host}:{port}"))?;

            addrs.push(url);
        }

        Ok(addrs)
    }
}

pub(crate) struct To1<T> {
    device_creds: DeviceCredential<'static>,
    state: T,
}

pub(crate) struct Hello {}

impl To1<Hello> {
    pub(crate) fn new(device_creds: DeviceCredential<'static>) -> Self {
        Self {
            device_creds,
            state: Hello {},
        }
    }

    pub(crate) async fn rv_owner<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<RvRedirect>
    where
        C: Crypto,
        S: Storage,
    {
        let ack = self.run(ctx).await?;

        let prove = ack.run(ctx).await?;

        let addr = prove.run().await?;

        info!("To1 Done");

        Ok(addr)
    }

    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<To1<Ack>>
    where
        C: Crypto,
    {
        let mut delay = None;

        for i in self.device_creds.dc_rv_info.iter() {
            if let Some(delay) = delay {
                self.wait_for(delay).await?
            }

            let Some(rv) = RvDevBuilder::try_from(i)? else {
                continue;
            };

            if let Some(prove) = self.follow_instr(ctx, &rv).await? {
                info!("To1.HelloRv done");

                return Ok(To1 {
                    device_creds: self.device_creds,
                    state: prove,
                });
            }

            delay.replace(rv.delay());
        }

        // TODO: impl retry
        Err(eyre!("nothing matched, should retry"))
    }

    async fn follow_instr<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        rv: &RvDevBuilder<'_>,
    ) -> eyre::Result<Option<Ack>>
    where
        C: Crypto,
    {
        match rv.protocol() {
            RvProtocolValue::Rest => {
                if let Some(ack) = self.http_instr(ctx, rv).await? {
                    return Ok(Some(ack));
                }

                if let Some(ack) = self.https_instr(ctx, rv).await? {
                    return Ok(Some(ack));
                }

                Ok(None)
            }
            RvProtocolValue::Http => {
                if let Some(ack) = self.http_instr(ctx, rv).await? {
                    return Ok(Some(ack));
                }

                Ok(None)
            }
            RvProtocolValue::Https => {
                if let Some(ack) = self.https_instr(ctx, rv).await? {
                    return Ok(Some(ack));
                }

                Ok(None)
            }
            RvProtocolValue::Tcp
            | RvProtocolValue::Tls
            | RvProtocolValue::CoapTcp
            | RvProtocolValue::CoapUdp => {
                error!("protocol not supported");

                Ok(None)
            }
        }
    }

    async fn http_instr<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        rv: &RvDevBuilder<'_>,
    ) -> Result<Option<Ack>, eyre::Error>
    where
        C: Crypto,
    {
        let urls = rv.http_urls()?;

        for url in urls {
            debug!(%url, "contacting rv");

            match self.http(ctx, url).await {
                Ok((ack, client)) => {
                    debug!(?ack, "ack received");

                    return Ok(Some(Ack {
                        client,
                        nonce: ack.nonce_to1_proof,
                    }));
                }
                Err(err) => {
                    error!(
                        error = format!("{err:#}"),
                        "failure wile contacting rv server"
                    )
                }
            }
        }

        Ok(None)
    }

    async fn https_instr<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        rv: &RvDevBuilder<'_>,
    ) -> Result<Option<Ack>, eyre::Error>
    where
        C: Crypto,
    {
        let urls = rv.https_urls()?;

        for url in urls {
            debug!(%url, "contacting rv");

            match self.https(ctx, url).await {
                Ok((ack, client)) => {
                    debug!(?ack, "ack received");

                    return Ok(Some(Ack {
                        client,
                        nonce: ack.nonce_to1_proof,
                    }));
                }
                Err(err) => {
                    error!(
                        error = format!("{err:#}"),
                        "failure wile contacting rv server"
                    )
                }
            }
        }

        Ok(None)
    }

    async fn http<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        url: Url,
    ) -> eyre::Result<(HelloRvAck<'static>, Client)>
    where
        C: Crypto,
    {
        let client = Client::new(url)?;

        let sg_type = ctx.crypto.sign_info_type();

        let (ack, auth) = client
            .init(&HelloRv {
                guid: self.device_creds.dc_guid,
                e_a_sig_info: EASigInfo(SigInfo {
                    sg_type,
                    info: std::borrow::Cow::Owned(ByteBuf::new()),
                }),
            })
            .await?;

        Ok((ack, client.set_auth(auth)))
    }

    // TODO: check the certificate validity following the spec
    async fn https<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        url: Url,
    ) -> eyre::Result<(HelloRvAck<'static>, Client)>
    where
        C: Crypto,
    {
        let client = Client::new(url)?;

        let (ack, auth) = client
            .init(&HelloRv {
                guid: self.device_creds.dc_guid,
                e_a_sig_info: EASigInfo(SigInfo {
                    sg_type: ctx.crypto.sign_info_type(),
                    info: std::borrow::Cow::Owned(ByteBuf::new()),
                }),
            })
            .await?;

        Ok((ack, client.set_auth(auth)))
    }

    async fn wait_for(&self, mut delay: Duration) -> eyre::Result<()> {
        // random range up to 25%
        let add = i64::try_from(delay.as_secs().div_euclid(100).saturating_mul(25))?;

        let range = rand::random_range(-add..add);

        let add = Duration::from_secs(range.unsigned_abs());

        if range.is_negative() {
            delay -= add;
        } else {
            delay += add;
        }

        info!("waiting for {}s before retrying", delay.as_secs());

        tokio::time::sleep(delay).await;

        Ok(())
    }
}

struct Ack {
    client: Client,
    nonce: NonceTo1Proof,
}

impl To1<Ack> {
    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<To1<Prove>>
    where
        C: Crypto,
    {
        let nonce = self.state.nonce.to_vec();
        let mut guid = vec![1u8; 17];

        guid.get_mut(1..)
            .ok_or_eyre("BUG: guid must be more then 1 byte")?
            .copy_from_slice(self.device_creds.dc_guid.as_ref());

        let payload = ciborium::Value::Map(vec![
            (EAT_NONCE.into(), ciborium::Value::Bytes(nonce)),
            (EAT_UEID.into(), ciborium::Value::Bytes(guid)),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf)?;

        let sign = ctx.crypto.cose_sing(HeaderBuilder::new(), buf).await?;

        info!("To1.HelloRvAck signed");

        Ok(To1 {
            device_creds: self.device_creds,
            state: Prove {
                client: self.state.client,
                proof: ProveToRv { ea_token: sign },
            },
        })
    }
}

struct Prove {
    client: Client,
    proof: ProveToRv,
}

impl To1<Prove> {
    async fn run(self) -> eyre::Result<RvRedirect> {
        let msg = self.state.client.send_msg(&self.state.proof).await?;

        info!("To1.ProveToRv sent");

        let addr = msg.rv_to2_addr()?;

        debug!(?addr);

        info!("To1.RVRedirect received");

        Ok(msg)
    }
}
