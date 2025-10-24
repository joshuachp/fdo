use std::path::PathBuf;

use clap::{Parser, Subcommand};
use eyre::eyre;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use self::client::Client;
use self::crypto::tpm::TpmCrypto;
use self::protocol::di::Di;
use self::protocol::v101::di::custom::MfgInfo;
use self::storage::FileStorage;

mod client;
mod crypto;
mod protocol;
mod storage;

const MANUFACTORER_URL: &str = "http://127.0.0.1:8038";

const SERIAL: &str = "e626207f-5fcc-456e-b1bc-250c9c8efb47";
const MODEL: &str = "fdo-astarte";

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, default_value = MANUFACTORER_URL)]
    manufactoring_url: url::Url,

    #[arg(long, default_value = SERIAL)]
    serial_no: String,

    #[arg(long, default_value = MODEL)]
    model_no: String,

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
    },
    PlainFs {
        #[arg(long, default_value = "/tmp/fdo-astarte")]
        storage: PathBuf,
    },
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

    let client = Client::new(cli.manufactoring_url)?;

    match cli.command {
        Command::UseTpm {
            tpm_connection,
            pcrs,
        } => {
            #[cfg(feature = "tpm")]
            let _tpm = TpmCrypto::create(tpm_connection, pcrs)?;
        }
        Command::PlainFs { storage } => {
            let storage = FileStorage::open(storage).await?;

            let mut crypto = crypto::software::SoftwareCrypto::create(storage.clone()).await?;

            let device_info = MfgInfo::generate(&mut crypto, &cli.serial_no, &cli.model_no).await?;

            let di = Di::new(client, crypto, storage);

            let _done = di.run(device_info).await?;
        }
    }

    Ok(())
}
