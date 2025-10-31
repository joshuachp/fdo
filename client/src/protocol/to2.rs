use std::marker::PhantomData;
use std::net::IpAddr;

use coset::iana::EnumI64;
use coset::{CoseEncrypt0, HeaderBuilder, TaggedCborSerializable};
use eyre::{Context, OptionExt, bail, ensure, eyre};
use reqwest::header::HeaderValue;
use tracing::{debug, error, info, instrument, warn};
use url::{Host, Url};

use crate::Ctx;
use crate::client::Client;
use crate::crypto::Crypto;
use crate::protocol::v101::eat_signature::{EAT_FDO, EAT_NONCE, EAT_UEID, EUPH_NONCE};
use crate::protocol::v101::error::{ErrorCode, ErrorMessage};
use crate::protocol::v101::service_info::ServiceInfo;
use crate::protocol::v101::to2::device_service_info::DeviceServiceInfo;
use crate::protocol::v101::to2::done::Done;
use crate::protocol::v101::to2::get_ov_next_entry::GetOvNextEntry;
use crate::protocol::v101::to2::prove_device::ProveDevice;
use crate::protocol::v101::{NonceTo2SetupDv, TransportProtocol};

use super::CborBstr;
use super::v101::device_credentials::DeviceCredential;
use super::v101::hash_hmac::Hash;
use super::v101::key_exchange::XAKeyExchange;
use super::v101::ownership_voucher::OvHeader;
use super::v101::public_key::PublicKey;
use super::v101::rv_to2_addr::{RvTo2Addr, RvTo2AddrEntry};
use super::v101::sign_info::{EASigInfo, EBSigInfo, SigInfo};
use super::v101::to1::rv_redirect::RvRedirect;
use super::v101::to2::device_service_info_ready::DeviceServiceInfoReady;
use super::v101::to2::hello_device::HelloDevice;
use super::v101::to2::ov_next_entry::OvNextEntry;
use super::v101::to2::prove_ov_hdr::{ProveOvHdr, PvOvHdrPayload, PvOvHdrUnprotected};
use super::v101::{Message, NonceTo2ProveDv, NonceTo2ProveOv};

#[derive(Debug)]
enum Address {
    Http(Url),
}

impl Address {
    fn http(
        idx: usize,
        acc: &mut Vec<Self>,
        schema: &'static str,
        addr: &RvTo2AddrEntry,
    ) -> eyre::Result<()> {
        if addr.rv_dns.is_none() && addr.rv_ip.is_none() {
            bail!("address {idx} is missing both ip and domain name");
        }

        if let Some(dns) = &addr.rv_dns {
            debug!(idx, %dns, "adding dns address");

            let url = Url::parse(&format!("{schema}://{dns}:{}", addr.rv_port))?;

            acc.push(Address::Http(url));
        }

        if let Some(ip) = &addr.rv_ip {
            let ip = IpAddr::from(*ip);

            debug!(idx, %ip, "adding ip address");

            let host: Host<String> = match ip {
                IpAddr::V4(ipv4_addr) => Host::Ipv4(ipv4_addr),
                IpAddr::V6(ipv6_addr) => Host::Ipv6(ipv6_addr),
            };

            let url = Url::parse(&format!("{schema}://{host}:{}", addr.rv_port))?;

            acc.push(Address::Http(url));
        }

        Ok(())
    }
}

impl TryFrom<RvTo2Addr<'_>> for Vec<Address> {
    type Error = eyre::Report;

    fn try_from(value: RvTo2Addr) -> Result<Self, Self::Error> {
        value
            .iter()
            .enumerate()
            .try_fold(Vec::new(), |mut acc, (idx, addr)| {
                match addr.rv_protocol {
                    TransportProtocol::Http => {
                        Address::http(idx, &mut acc, "http", addr)?;
                    }
                    TransportProtocol::Https => {
                        Address::http(idx, &mut acc, "https", addr)?;
                    }
                    TransportProtocol::Tcp
                    | TransportProtocol::Tls
                    | TransportProtocol::CoAp
                    | TransportProtocol::CoAps => {
                        warn!(protocol = ?addr.rv_protocol, "not supported");
                    }
                }

                Ok(acc)
            })
    }
}

pub(crate) struct To2<S> {
    device_creds: DeviceCredential<'static>,
    state: S,
}

impl To2<Hello> {
    pub(crate) fn create(
        device_creds: DeviceCredential<'static>,
        rv: RvRedirect,
    ) -> eyre::Result<Self> {
        let addresses = rv.rv_to2_addr()?.to1d_rv.try_into()?;

        let state = Hello { rv, addresses };

        Ok(Self {
            device_creds,
            state,
        })
    }

    pub(crate) async fn to2_change<C, S>(
        self,
        ctx: &mut Ctx<'_, C, S>,
    ) -> eyre::Result<ServiceInfo<'static>>
    where
        C: Crypto,
    {
        info!("To2 started");

        let prove_ov = self.run(ctx).await?;
        let verify = prove_ov.run(ctx).await?;
        let prove_dv = verify.run(ctx).await?;
        let setup = prove_dv.run(ctx).await?;
        let ready = setup.run(ctx).await?;
        let srv_info = ready.run(ctx).await?;

        info!("TO2 finished sucessfully 🎉");

        Ok(srv_info)
    }
}

pub(crate) struct Hello {
    rv: RvRedirect,
    addresses: Vec<Address>,
}

impl To2<Hello> {
    async fn hello<C, S>(&self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<HelloDevice<'static>>
    where
        C: Crypto,
    {
        let nonce = ctx.crypto.create_nonce().await.map(NonceTo2ProveOv)?;

        Ok(HelloDevice {
            max_device_message_size: 0,
            guid: self.device_creds.dc_guid,
            nonce,
            kex_suite_name: ctx.crypto.kex_suit().as_str().into(),
            cipher_suite_name: ctx.crypto.cipher_suite().to_i64(),
            ea_sign_info: EASigInfo(SigInfo {
                sg_type: ctx.crypto.sign_info_type(),
                info: Default::default(),
            }),
        })
    }

    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<To2<Prove>>
    where
        C: Crypto,
    {
        for addr in &self.state.addresses {
            match addr {
                Address::Http(url) => match self.http(ctx, url).await {
                    Ok((hello_device, hdr, client)) => {
                        return Ok(To2 {
                            device_creds: self.device_creds,
                            state: Prove {
                                hello_device,
                                rv: self.state.rv,
                                hdr,
                                client,
                            },
                        });
                    }
                    Err(err) => {
                        error!(error = format!("{err:#}"), "tried connecting to server")
                    }
                },
            }
        }

        Err(eyre!("couldn't connect to the ownerhsip server"))
    }

    async fn http<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        base_url: &Url,
    ) -> eyre::Result<(HelloDevice<'static>, ProveOvHdr, Client)>
    where
        C: Crypto,
    {
        let client = Client::new(base_url.clone())?;

        let hello = self.hello(ctx).await?;

        let (pv_ov, auth) = client.init(&hello).await?;

        Ok((hello, pv_ov, client.set_auth(auth)))
    }
}

struct Prove {
    hello_device: HelloDevice<'static>,
    rv: RvRedirect,
    hdr: ProveOvHdr,
    client: Client,
}

impl To2<Prove> {
    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<To2<VerifyChain>>
    where
        C: Crypto,
    {
        let payload = self.state.hdr.paylod()?;
        let hdr = self.state.hdr.header()?;

        let enc = CoseEncrypt0::from_tagged_slice(&self.device_creds.dc_hmac_secret)?;

        // 1. Verify with CUPH owner key
        C::verify_cose_singature(&self.state.rv.to1d, &hdr.cuph_owner_pubkey)?;

        info!("TO2.ProveOvHdr RvRedirect verified");

        C::verify_cose_singature(&self.state.hdr.sign, &hdr.cuph_owner_pubkey)?;

        info!("TO2.ProveOvHdr ProveOvHdr verified");

        // 2. Verify OVHeder against device credentials
        let mut buf = Vec::new();
        ciborium::into_writer(&payload.ov_header.ov_pub_key, &mut buf)?;
        C::verify_hash(&self.device_creds.dc_pub_key_hash, &buf)?;

        info!("TO2.ProveOvHdr OVPubKey verified");

        let data = payload.ov_header.bytes()?;

        ctx.crypto.verify_hmac(&enc, &payload.hmac, data).await?;

        info!("TO2.ProveOvHdr Hmac verified");

        // TODO: key exchange

        // 3. Verify HelloDevice hash
        buf.clear();
        ciborium::into_writer(&self.state.hello_device, &mut buf)?;

        let res = C::verify_hash(&payload.hello_device_hash, &buf)
            .wrap_err("couldn't verify HelloDevice");

        if let Err(err) = res {
            let err_msg = ErrorMessage::new(
                ErrorCode::MessageBodyError,
                ProveOvHdr::MSG_TYPE as u8,
                "failed to validate HelloDevice hash".into(),
                // Make go server client happy
                ciborium::Value::Integer(0.into()),
                None,
            );

            self.state.client.send_err(&err_msg).await;

            return Err(err);
        }

        info!("TO2.ProveOvHdr HelloDevice verified");

        // 4. Create variable to validate the chain
        let dev_chain_hash = payload
            .ov_header
            .ov_dev_cert_chain_hash
            .as_ref()
            .ok_or_eyre("missing device chain hash")?
            .clone()
            .into_owned();

        Ok(To2 {
            device_creds: self.device_creds,
            state: VerifyChain {
                hdr,
                payload,
                full: self.state.hdr,
                dev_chain_hash,
                client: self.state.client,
            },
        })
    }
}

struct VerifyChain {
    full: ProveOvHdr,
    payload: PvOvHdrPayload<'static>,
    hdr: PvOvHdrUnprotected<'static>,
    dev_chain_hash: Hash<'static>,
    client: Client,
}

impl To2<VerifyChain> {
    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<To2<ProveDv>>
    where
        C: Crypto,
    {
        let num_ov_entries = self.state.payload.num_ov_entries;

        ensure!(
            num_ov_entries != 0,
            "number of entries must be greater than 0"
        );

        debug!(num_ov_entries, "checking entries");

        let mut buf = Vec::new();

        // SHA[TO2.ProveOVHdr.OVHeader||TO2.ProveOVHdr.HMac] (no cbor hdr)
        let mut hash_prev_entry = self.state.payload.ov_header.bytes()?.to_vec();
        ciborium::into_writer(&self.state.payload.hmac, &mut buf)?;
        hash_prev_entry.extend_from_slice(&buf);

        // SHA[TO2.ProveOVHdr.OVHeader.Guid||TO2.ProveOVHdr.OVHeader.DeviceInfo]
        let mut hash_hdr_info = self.state.payload.ov_header.ov_guid.to_vec();
        hash_hdr_info.extend_from_slice(self.state.payload.ov_header.ov_device_info.as_bytes());

        let mut variable = Variables {
            hash_prev_entry,
            pub_key: self.state.payload.ov_header.ov_pub_key.clone(),
            hash_hdr_info,
        };

        for ov_entry_num in 0..num_ov_entries {
            let entry = self
                .state
                .client
                .send_msg(&GetOvNextEntry { ov_entry_num })
                .await?;

            info!("To2.GetOvNextEntry sent");

            debug!(ov_entry_num, "entry received, validating");

            self.validate(ctx, &mut variable, entry)?;

            info!("To2.OvNextEntry validated");
        }

        // 6. If OVEntryNum == TO2.ProveOpHdr.NumOVEntries-1 then verify
        //    TO2.ProveOVHdr.pk == TO2.OVNextEntry.OVNextEntry.OVPubKey
        if variable.pub_key.key() != self.state.hdr.cuph_owner_pubkey.key() {
            debug!(
                k1 = ?variable.pub_key,
                k2 = ?self.state.hdr.cuph_owner_pubkey,
                "final key missmatch"
            );

            bail!("final key mismatch")
        }

        C::verify_cose_singature(&self.state.full.sign, &variable.pub_key)?;

        info!("To2.OvNextEntry chain verified");

        Ok(To2 {
            device_creds: self.device_creds,
            state: ProveDv {
                ov_header: self.state.payload.ov_header,
                ow_pubkey: variable.pub_key,
                owner_sing_info: self.state.payload.eb_sign_info,
                nonce_to2_prove_dv: self.state.hdr.cuph_nonce,
                x_a_key_exchange: self.state.payload.x_a_key_exchange,
                client: self.state.client,
            },
        })
    }

    /// Validate an ownership voucher entry.
    ///
    /// 1. Verify signature TO2.OVNextEntry.OVEntry using variable PubKey
    /// 2. Verify variable HashHdrInfo matches TO2.OVEntry.OVEHashHdrInfo
    /// 3. Verify HashPrevEntry matches SHA[TO2.OpNextEntry.OVEntry.OVEPubKey]
    /// 4. Update variable PubKey to TO2.OVNextEntry.OVEPubKey.OVPubKey
    /// 5. Update variable HashPrevEntry to SHA[TO2.OpNextEntryPayload]
    ///
    /// Last step is done outside
    #[instrument(skip_all, fields(nbr = entry.ov_entry_num))]
    fn validate<C, S>(
        &self,
        _ctx: &mut Ctx<'_, C, S>,
        variables: &mut Variables,
        entry: OvNextEntry,
    ) -> eyre::Result<()>
    where
        C: Crypto,
    {
        // 1. Verify signature TO2.OVNextEntry.OVEntry using variable PubKey
        C::verify_cose_singature(&entry.ov_entry.entry, &variables.pub_key)
            .wrap_err("validating entry signature")?;
        info!("cose signature verified");

        // 2. Verify variable HashHdrInfo matches TO2.OVEntry.OVEHashHdrInfo
        let (entry, payload) = entry.ov_entry.payload()?;

        C::verify_hash(&payload.ov_e_hash_hdr_info, &variables.hash_hdr_info)
            .wrap_err("validating hash hdr info")?;
        info!("hash hdr info verified");

        // 3. Verify HashPrevEntry matches SHA[TO2.OpNextEntry.OVEntry.OVEPubKey]
        C::verify_hash(&payload.ov_e_hash_prev_entry, &variables.hash_prev_entry)
            .wrap_err("validating ove pubkey hash")?;
        info!("hash prev entry verified");

        // 4. Update variable PubKey to TO2.OVNextEntry.OVEPubKey.OVPubKey
        variables.pub_key = payload.ov_e_pubkey;

        // 5. Update variable HashPrevEntry to SHA[TO2.OpNextEntryPayload] (this is wrong)
        variables.hash_prev_entry = entry;

        Ok(())
    }
}

/// Variables steps:
/// - **HashPrevEntry** – hash of previous entry. The hash of the previous entry’s OVEntryPayload.
///   For the first entry, the hash is SHA[TO2.ProveOVHdr.OVHeader||TO2.ProveOVHdr.HMac]. The bstr
///   wrapping for the OVHeader is not included.
/// - **PubKey** – public key signed in previous entry (initialize with
///   TO2.ProveOVHdr.OVHeader.OVPubKey)
/// - **HashHdrInfo** – hash of GUID and DeviceInfo, compute from TO2.ProveOVHdr as:
///   SHA[TO2.ProveOVHdr.OVHeader.Guid||TO2.ProveOVHdr.OVHeader.DeviceInfo]
///   - Pad the hash text on the right with zeros to match the hash length.
struct Variables<'a> {
    hash_prev_entry: Vec<u8>,
    pub_key: PublicKey<'a>,
    hash_hdr_info: Vec<u8>,
}

struct ProveDv {
    ov_header: CborBstr<'static, OvHeader<'static>>,
    ow_pubkey: PublicKey<'static>,
    owner_sing_info: EBSigInfo<'static>,
    nonce_to2_prove_dv: NonceTo2ProveDv,
    x_a_key_exchange: XAKeyExchange<'static>,
    client: Client,
}

impl To2<ProveDv> {
    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<To2<Setup<C>>>
    where
        C: Crypto,
    {
        let (xb, key) = ctx
            .crypto
            .key_exchange(&self.state.x_a_key_exchange)
            .await?;

        info!("To2.ProveDevice key exchange done");

        // TODO: deduplicate
        let mut guid = vec![1u8; 17];
        guid.get_mut(1..)
            .ok_or_eyre("BUG: guid must be more then 1 byte")?
            .copy_from_slice(self.device_creds.dc_guid.as_ref());

        let prv_dv_payload = ciborium::Value::Array(vec![ciborium::Value::Bytes(xb.0.to_vec())]);

        let payload = ciborium::Value::Map(vec![
            (
                EAT_NONCE.into(),
                ciborium::Value::Bytes(self.state.nonce_to2_prove_dv.0.to_vec()),
            ),
            (EAT_UEID.into(), ciborium::Value::Bytes(guid)),
            (EAT_FDO.into(), prv_dv_payload),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf)?;

        let nonce_setup_dv = NonceTo2SetupDv(ctx.crypto.create_nonce().await?);

        let unprotected = HeaderBuilder::new().value(
            EUPH_NONCE,
            ciborium::Value::Bytes(nonce_setup_dv.0.to_vec()),
        );

        let sign = ctx.crypto.cose_sing(unprotected, buf).await?;

        let prove_dv = ProveDevice { sign };

        Ok(To2 {
            device_creds: self.device_creds,
            state: Setup {
                ov_header: self.state.ov_header,
                nonce_setup_dv,
                prove_dv,
                client: self.state.client,
                key,
                _marker: PhantomData,
                nonce_to2_prove_dv: self.state.nonce_to2_prove_dv,
            },
        })
    }
}

struct Setup<C>
where
    C: Crypto,
{
    ov_header: CborBstr<'static, OvHeader<'static>>,
    nonce_to2_prove_dv: NonceTo2ProveDv,
    nonce_setup_dv: NonceTo2SetupDv,
    prove_dv: ProveDevice,
    client: Client,
    key: C::KeyExchange,
    _marker: PhantomData<C>,
}

impl<C> To2<Setup<C>>
where
    C: Crypto,
{
    async fn run<S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<To2<DvReady<C>>>
    where
        C: Crypto,
    {
        let setup_dv = self
            .state
            .client
            .init_enc(ctx, &self.state.key, &self.state.prove_dv)
            .await?;

        info!("To2.ProveDevice succeded");

        let payload = setup_dv.payload()?;

        C::verify_cose_singature(&setup_dv.sign, &payload.owner_2_key)?;
        info!("To2.SetupDevice singature verified");

        ensure!(payload.nonce_to2_setup_dv == self.state.nonce_setup_dv);
        info!("To2.SetupDevice nonce verified");

        let client = self.state.client.set_enckey(self.state.key);

        info!("To2.SetupDevice done");

        let hmac_secret = CoseEncrypt0::from_tagged_slice(&self.device_creds.dc_hmac_secret)?;
        let hmac = ctx
            .crypto
            .hmac(&hmac_secret, self.state.ov_header.bytes()?)
            .await?;

        Ok(To2 {
            device_creds: self.device_creds,
            state: DvReady {
                dv_srv_info_ready: DeviceServiceInfoReady {
                    replacement_hmac: Some(hmac),
                    max_owner_service_info_sz: None,
                },
                client,
                _marker: PhantomData,
                nonce_to2_prove_dv: self.state.nonce_to2_prove_dv,
                nonce_to2_setup_dv: self.state.nonce_setup_dv,
            },
        })
    }
}

struct DvReady<C>
where
    C: Crypto,
{
    dv_srv_info_ready: DeviceServiceInfoReady<'static>,
    nonce_to2_prove_dv: NonceTo2ProveDv,
    nonce_to2_setup_dv: NonceTo2SetupDv,
    client: Client<HeaderValue, C::KeyExchange>,
    _marker: PhantomData<C>,
}

impl<C> To2<DvReady<C>>
where
    C: Crypto,
{
    async fn run<S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<ServiceInfo<'static>>
    where
        C: Crypto,
    {
        let own_srv_info_ready = self
            .state
            .client
            .send_enc(ctx, &self.state.dv_srv_info_ready)
            .await?;

        info!(
            srv_max = own_srv_info_ready.max_device_service_info_sz,
            "TO2.DeviceServiceInfoReady done"
        );

        // TODO: this part should be improved
        let device_srv_info = DeviceServiceInfo::example();

        let mut srv_info = Vec::new();
        loop {
            info!("TO2.DeviceServiceInfo started");

            let own_srv_info = self.state.client.send_enc(ctx, &device_srv_info).await?;

            debug!(?own_srv_info, "Owner service info");

            info!(
                len = own_srv_info.service_info.len(),
                "TO2.OwnerServiceInfo received"
            );

            srv_info.extend(own_srv_info.service_info);

            if own_srv_info.is_done {
                break;
            }
        }

        info!("TO2.OwnerServiceInfo done");

        // TODO: replace the new StupDevice information

        let done = self
            .state
            .client
            .send_enc(
                ctx,
                &Done {
                    nonce_to2_prove_dv: self.state.nonce_to2_prove_dv,
                },
            )
            .await?;

        ensure!(done.nonce_to2_setup_dv == self.state.nonce_to2_setup_dv);

        info!("TO2.Done finished");

        Ok(srv_info)
    }
}
