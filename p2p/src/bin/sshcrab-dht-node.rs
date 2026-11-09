//! sshcrab-dht-node: a long-running DHT node to bootstrap from, such as
//! bootstrap.nixcloud.io (spec §13.6). Carries no sshcrab traffic.

use clap::Parser;
use sshcrab_proto::p2p::DHT_NODE_PORT;

#[derive(Parser)]
#[command(name = "sshcrab-dht-node", version, about = "DHT bootstrap node for sshcrab")]
struct Args {
    /// Address to bind: the node's public IPv4 address; 0.0.0.0 only together
    /// with --public or --bootstrap, from which it learns its address.
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    /// UDP port (must be reachable from the internet).
    #[arg(short, long, default_value_t = DHT_NODE_PORT)]
    port: u16,
    /// Other nodes to join (`host:port` or `ip@host:port`); repeatable.
    #[arg(long)]
    bootstrap: Vec<String>,
    /// Also join the public HyperDHT network through its bootstrap nodes.
    #[arg(long)]
    public: bool,
}

fn main() -> std::process::ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let mut args = Args::parse();
    if nix::unistd::Uid::effective().is_root() {
        eprintln!("sshcrab-dht-node: refusing to run as root");
        return std::process::ExitCode::from(2);
    }
    if args.public {
        args.bootstrap.extend(peeroxide::DEFAULT_BOOTSTRAP.iter().map(|s| s.to_string()));
    }
    // A node's DHT id derives from its public address. Bound to a wildcard it
    // learns that address from other nodes; a first node without any never does.
    if (args.host == "0.0.0.0" || args.host == "::") && args.bootstrap.is_empty() {
        eprintln!("sshcrab-dht-node: with no other nodes to join (--public or --bootstrap), --host must be this node's public IPv4 address");
        return std::process::ExitCode::from(2);
    }
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let (handle, task) = match sshcrab_p2p::run_node(&args.host, args.port, &args.bootstrap).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("starting the DHT node: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let port = handle.local_port().await.unwrap_or(args.port);
        log::info!("DHT node on {}:{port} ({} bootstrap nodes)", args.host, args.bootstrap.len());
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
            _ = task => {
                log::error!("the DHT node stopped");
                return std::process::ExitCode::FAILURE;
            }
        }
        let _ = handle.destroy().await;
        std::process::ExitCode::SUCCESS
    })
}
