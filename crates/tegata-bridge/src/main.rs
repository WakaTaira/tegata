#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
use clap::Parser;

#[cfg(unix)]
use tegata_bridge::{BridgeConfig, run};

#[cfg(unix)]
#[derive(Debug, Parser)]
#[command(name = "tegata-bridge")]
struct Args {
    #[arg(long)]
    socket: PathBuf,
    #[arg(long = "token-file")]
    token_file: PathBuf,
    #[arg(long = "daemon-addr")]
    daemon_addr: Option<String>,
}

#[cfg(unix)]
#[tokio::main]
async fn main() {
    let args = Args::parse();
    let daemon_addr = match args.daemon_addr {
        Some(addr) => addr,
        None => match tegata_bridge::default_daemon_addr() {
            Ok(addr) => addr,
            Err(error) => {
                eprintln!("tegata-bridge: {error}");
                std::process::exit(1);
            }
        },
    };

    if let Err(error) = run(BridgeConfig {
        socket_path: args.socket,
        token_file: args.token_file,
        daemon_addr,
    })
    .await
    {
        eprintln!("tegata-bridge: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn main() {
    eprintln!("tegata-bridge is supported only on Unix");
    std::process::exit(1);
}
