//! Read-only comparison of peer checkpoint certificates with a live local
//! registry snapshot. Candidate committees are hypotheses, not historical
//! authorization. Session certificates require the normal handoff validator.

use std::{path::PathBuf, time::Duration};

use clap::Parser;
use quil_keys::KeyManager as _;
use quil_types::consensus::ProverRegistry as _;
use serde_json::json;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = ".config")]
    config: PathBuf,
    #[arg(long)]
    master_store: PathBuf,
    #[arg(long, value_delimiter = ',')]
    peers: Vec<String>,
    #[arg(long, value_delimiter = ',')]
    filters: Vec<String>,
    #[arg(long, default_value_t = 720)]
    epoch_length: u64,
}

async fn bounded<T, E: std::fmt::Display>(
    call: impl std::future::Future<Output = Result<T, E>>,
) -> anyhow::Result<T> {
    tokio::time::timeout(Duration::from_secs(30), call)
        .await?
        .map_err(|e| anyhow::anyhow!("{e}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    anyhow::ensure!(args.epoch_length > 0, "epoch length must be positive");
    anyhow::ensure!(
        !args.peers.is_empty() && args.peers.len() <= 8,
        "require 1–8 peers"
    );
    anyhow::ensure!(
        !args.filters.is_empty() && args.filters.len() <= 32,
        "require 1–32 filters"
    );
    let filters = args
        .filters
        .iter()
        .map(|s| {
            let filter = hex::decode(s)?;
            anyhow::ensure!(
                quil_forest::decode_shard_filter_or_root(&filter, 32).is_some(),
                "invalid filter"
            );
            Ok(filter)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    quil_crypto::init();
    quil_types::consensus::set_epoch_length_frames(args.epoch_length);
    let db = quil_store::RocksDb::open_for_read_only_live(&args.master_store)?;
    let registry = quil_execution::prover_registry::SharedProverRegistry::new();
    registry.refresh_from_store(&quil_store::RocksHypergraphStore::new(db.inner()))?;
    let clock = quil_store::RocksClockStore::new(db.inner());
    use quil_types::store::ClockStore as _;
    let census = clock
        .get_latest_global_clock_frame()?
        .header
        .ok_or_else(|| anyhow::anyhow!("no local head"))?
        .frame_number;
    let config = quil_config::load_config(&args.config)?;
    let keys_path = if config.key.key_store_file.path.is_empty() {
        args.config.join("keys.yml")
    } else {
        PathBuf::from(&config.key.key_store_file.path)
    };
    let proving_key_id = if config.engine.proving_key_id.is_empty() {
        "default-proving-key".to_string()
    } else {
        config.engine.proving_key_id.clone()
    };
    let keys = quil_keys::FileKeyManager::new(
        keys_path,
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(quil_crypto::FalconKeyConstructor),
    )?;
    keys.set_peer_priv_key_hex(&config.p2p.peer_priv_key);
    // No ensure_standard_keys: this tool never creates or rewrites identity.
    let key = keys.get_private_key(quil_types::crypto::KeyType::Falcon512)?;
    println!(
        "{}",
        json!({"local_census_frame":census,"epoch_length":args.epoch_length,
        "evidence":"peer checkpoints and current local registry; not historical authorization"})
    );
    for (peer_index, peer) in args.peers.iter().enumerate() {
        let mut client = match bounded(quil_rpc::ArchiveClient::connect_mtls(peer, &key)).await {
            Ok(client) => client,
            Err(error) => {
                println!(
                    "{}",
                    json!({"peer_index":peer_index,"unavailable":error.to_string()})
                );
                continue;
            }
        };
        for (filter_index, filter) in filters.iter().enumerate() {
            let frame = match bounded(client.get_app_shard_frame(filter.clone(), 0)).await {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    println!(
                        "{}",
                        json!({"peer_index":peer_index,"filter_index":filter_index,"checkpoint":"not served"})
                    );
                    continue;
                }
                Err(error) => {
                    println!(
                        "{}",
                        json!({"peer_index":peer_index,"filter_index":filter_index,"unavailable":error.to_string()})
                    );
                    continue;
                }
            };
            let Some(header) = frame.header.as_ref().filter(|h| &h.address == filter) else {
                println!(
                    "{}",
                    json!({"peer_index":peer_index,"filter_index":filter_index,"checkpoint":"missing or wrong-shard header"})
                );
                continue;
            };
            let cert = header
                .public_key_signature_bls48581
                .as_ref()
                .and_then(|s| quil_cw_consensus::app_cert::unwrap_cert_from_header(&s.signature));
            let epoch = cert.and_then(quil_cw_consensus::app_cert::unverified_finalization_epoch);
            let mut comparisons = Vec::new();
            if let Some(cert) = cert.filter(|_| epoch == Some(0)) {
                let digest = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?;
                let namespace = [b"appshard".as_slice(), filter.as_slice()].concat();
                for (basis, frame) in [
                    ("registry_at_claimed_anchor", header.global_frame_number),
                    ("registry_at_local_census", census),
                ] {
                    let members: Vec<_> = registry
                        .get_active_provers(filter, frame)?
                        .into_iter()
                        .map(|p| p.public_key)
                        .collect();
                    let outcome = quil_cw_consensus::app_cert::check_finalization(
                        cert, &members, &namespace, digest,
                    )
                    .map(|_| "verifies".to_string())
                    .unwrap_or_else(|e| format!("{e:?}"));
                    comparisons
                        .push(json!({"basis":basis,"members":members.len(),"result":outcome}));
                }
                let all: Vec<_> = registry
                    .get_provers(filter)?
                    .into_iter()
                    .map(|p| p.public_key)
                    .collect();
                let identified =
                    quil_cw_consensus::app_cert::identify_signers(cert, &namespace, &all);
                comparisons.push(
                    json!({"basis":"individual_signatures_among_current_filter_allocations",
                    "identified":identified.as_ref().map(Vec::len),"candidates":all.len()}),
                );
            }
            println!(
                "{}",
                json!({"peer_index":peer_index,"filter_index":filter_index,
                "checkpoint_frame":header.frame_number,"claimed_global_anchor":header.global_frame_number,
                "claimed_cert_epoch":epoch,"claimed_signer_counts":cert.and_then(quil_cw_consensus::app_cert::unverified_signers),
                "comparisons":comparisons,"session_note":if epoch.is_some_and(|e|e>0){Some("requires authenticated handoff validator")}else{None}})
            );
        }
    }
    // Keep the read-only DB alive throughout the registry comparisons.
    drop(db);
    Ok(())
}
