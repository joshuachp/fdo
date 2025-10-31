use std::path::PathBuf;

use clap::{Parser, Subcommand};
use eyre::{bail, eyre};
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use self::client::Client;
use self::crypto::Crypto;
use self::crypto::tpm::TpmCrypto;
use self::protocol::di::Di;
use self::protocol::to1::To1;
use self::protocol::to2::To2;
use self::protocol::v101::di::custom::MfgInfo;
use self::storage::{FileStorage, Storage};

mod client;
mod crypto;
mod protocol;
mod storage;

#[derive(Debug)]
struct Ctx<'a, C, S> {
    crypto: &'a mut C,
    storage: &'a mut S,
}

const MANUFACTORER_URL: &str = "http://127.0.0.1:8038";

const SERIAL: &str = "e626207f-5fcc-456e-b1bc-250c9c8efb47";
const MODEL: &str = "fdo-astarte";

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    UseTpm {
        /// TPM connecting string `device:/dev/tpmrm0`
        #[arg(long)]
        tpm_connection: Option<String>,

        /// PCRs registers to measure
        ///
        /// Defaults to: 0,2,4,6    Firmware
        ///              7          Secure Boot
        #[arg(long, default_values_t = vec![0,2,4,6,7])]
        pcrs: Vec<u8>,

        #[command(subcommand)]
        proto: Protocol,
    },
    PlainFs {
        #[arg(long, default_value = "/tmp/fdo-astarte")]
        storage: PathBuf,

        #[command(subcommand)]
        proto: Protocol,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum Protocol {
    Inspect,
    Di {
        #[arg(long, default_value = MANUFACTORER_URL)]
        manufactoring_url: url::Url,

        #[arg(long, default_value = SERIAL)]
        serial_no: String,

        #[arg(long, default_value = MODEL)]
        model_no: String,
    },
    To {},
}

impl Protocol {
    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<()>
    where
        C: Crypto,
        S: Storage,
    {
        match self {
            Protocol::Inspect => {
                let Some(dc) = Di::read_existing(ctx).await? else {
                    info!("device credentials missing, DI not yet completed");

                    return Ok(());
                };

                info!(?dc);
            }
            Protocol::Di {
                manufactoring_url,
                serial_no,
                model_no,
            } => {
                let client = Client::new(manufactoring_url)?;

                let device_info = MfgInfo::generate(ctx.crypto, &serial_no, &model_no).await?;

                let di = Di::new(client, device_info);

                let done = di.create_credentials(ctx).await?;

                info!(guid = %done.dc_guid, "device initialized");
            }
            Protocol::To {} => {
                let Some(dc) = Di::read_existing(ctx).await? else {
                    bail!("device credentials missing, DI not yet completed");
                };

                // TODO: maybe pass a ref to dc?
                let rv = To1::new(dc.clone()).rv_owner(ctx).await?;

                To2::create(dc, rv)?.to2_change(ctx).await?;
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    color_eyre::install()?;

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive("info".parse()?)
                .from_env_lossy(),
        )
        .try_init()?;

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("couldn't install crypto provider"))?;

    match cli.command {
        Command::UseTpm {
            tpm_connection,
            pcrs,
            proto: _,
        } => {
            #[cfg(feature = "tpm")]
            let _tpm = TpmCrypto::create(tpm_connection, pcrs)?;
        }
        Command::PlainFs { storage, proto } => {
            let mut storage = FileStorage::open(storage).await?;

            let mut crypto = crypto::software::SoftwareCrypto::create(storage.clone()).await?;

            proto
                .run(&mut Ctx {
                    crypto: &mut crypto,
                    storage: &mut storage,
                })
                .await?;
        }
    }

    Ok(())
}
