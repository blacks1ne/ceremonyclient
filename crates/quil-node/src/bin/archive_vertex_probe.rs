//! Read-only archive probe for prover leaves and readable vertex blobs.
//!
//! These are peer-reported snapshots, not authenticated membership proofs.
//! Phase heads are read independently and may change during the probe. Errors
//! mean unavailable evidence, not an absent leaf. Historical blob reads use an
//! exact version, including version zero; latest is reported separately.
//! No local database is opened and no keys or configuration are written.

use std::path::PathBuf;

use clap::Parser;
use quil_keys::KeyManager as _;
use quil_rpc::ArchiveClient;

/// The global prover shard is a single-shard app at `l2 = [0xff; 32]`, and the
/// same value is `GLOBAL_INTRINSIC_ADDRESS` — the app half of a 64-byte vertex
/// id. `l1` is the bloom prefix of `l2`, which is `[0; 3]` for a high first byte.
const PROVER_SHARD_L2: [u8; 32] = [0xffu8; 32];
const PROVER_SHARD_L1: [u8; 3] = [0u8; 3];

const PHASE_NAMES: [&str; 4] = [
    "vertex.adds",
    "vertex.removes",
    "hyperedge.adds",
    "hyperedge.removes",
];

#[derive(Parser)]
#[command(about = "Probe archive-reported prover leaves and vertex blobs")]
struct Args {
    /// Node config directory (holds config.yml and keys.yml).
    #[arg(long, default_value = ".config")]
    config: PathBuf,
    /// Comma-separated archive endpoints, `host:port`.
    #[arg(long)]
    peers: String,
    /// Comma-separated 32-byte hex prover addresses.
    #[arg(long)]
    addresses: String,
    /// Optional comma-separated tree versions. When given, the probe skips the
    /// per-phase report and instead asks, at each version, whether the phase-0
    /// leaf and the vertex blob exist — so the version at which a leaf first
    /// appeared (and whether its blob EVER accompanied it) can be bisected.
    #[arg(long)]
    versions: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let versions = args.versions.as_deref().map(parse_versions).transpose()?;

    let peers: Vec<String> = args
        .peers
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut addresses: Vec<Vec<u8>> = Vec::new();
    for a in args.addresses.split(',') {
        let a = a.trim();
        if a.is_empty() {
            continue;
        }
        let bytes = hex::decode(a)?;
        anyhow::ensure!(bytes.len() == 32, "address {a} is not 32 bytes");
        addresses.push(bytes);
    }
    anyhow::ensure!(!peers.is_empty(), "no peers given");
    anyhow::ensure!(!addresses.is_empty(), "no addresses given");

    // The node's own Falcon-512 q-prover-key is the :8340 network identity.
    // Loaded read-only: no `ensure_standard_keys`, so keys.yml is never written
    // while the service holds it.
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
    let key_manager = quil_keys::FileKeyManager::new(
        keys_path,
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(quil_crypto::FalconKeyConstructor),
    )?;
    key_manager.set_peer_priv_key_hex(&config.p2p.peer_priv_key);
    let falcon_signing_key = key_manager.get_private_key(quil_types::crypto::KeyType::Falcon512)?;

    for peer in &peers {
        println!("\n=== {peer} ===");
        let mut client = match rpc(ArchiveClient::connect_mtls(peer, &falcon_signing_key)).await {
            Ok(c) => c,
            Err(e) => {
                println!("  connect failed: {e}");
                continue;
            }
        };

        // Per-phase head of the prover shard. The version pins every
        // subsequent read to the tree the root commits to.
        let mut heads: [Option<(u64, Vec<u8>)>; 4] = [None, None, None, None];
        for phase in 0..4usize {
            heads[phase] =
                match rpc(client.get_forest_head(PROVER_SHARD_L2.to_vec(), phase as u32)).await {
                    Ok(head) => head,
                    Err(error) => {
                        println!("  head {:<18} unavailable: {error}", PHASE_NAMES[phase]);
                        continue;
                    }
                };
            match &heads[phase] {
                Some((v, root)) => println!(
                    "  head {:<18} version={} root={}",
                    PHASE_NAMES[phase],
                    v,
                    hex::encode(root)
                ),
                None => println!("  head {:<18} (absent)", PHASE_NAMES[phase]),
            }
        }

        if let Some(versions) = &versions {
            let shard_key: Vec<u8> = PROVER_SHARD_L1
                .iter()
                .copied()
                .chain(PROVER_SHARD_L2)
                .collect();
            for addr in &addresses {
                println!("  address {}", hex::encode(addr));
                let mut id = PROVER_SHARD_L2.to_vec();
                id.extend_from_slice(addr);
                for &v in versions {
                    let leaf =
                        rpc(client.get_forest_value(PROVER_SHARD_L2.to_vec(), 0, v, addr.clone()))
                            .await;
                    let blob =
                        rpc(client.get_vertex_blob_at(shard_key.clone(), 0, id.clone(), v)).await;
                    println!(
                        "    v={v:<8} leaf={} blob={}",
                        report_read(leaf),
                        report_read(blob)
                    );
                }
            }
            continue;
        }

        for addr in &addresses {
            println!("  address {}", hex::encode(addr));
            for phase in 0..4usize {
                let Some((version, _)) = heads[phase].clone() else {
                    continue;
                };
                match rpc(client.get_forest_value(
                    PROVER_SHARD_L2.to_vec(),
                    phase as u32,
                    version,
                    addr.clone(),
                ))
                .await
                {
                    Ok(Some(v)) => println!(
                        "    leaf {:<18} PRESENT  value={}",
                        PHASE_NAMES[phase],
                        hex::encode(&v)
                    ),
                    Ok(None) => println!("    leaf {:<18} absent", PHASE_NAMES[phase]),
                    Err(e) => println!("    leaf {:<18} error: {e}", PHASE_NAMES[phase]),
                }
            }

            // The blob is the readable vertex data the registry reads — the
            // half a tree-only sync can leave behind. Ask at the pinned
            // phase-0 version and separately at latest (`0`).
            let Some((version, _)) = heads[0].clone() else {
                continue;
            };
            let shard_key: Vec<u8> = PROVER_SHARD_L1
                .iter()
                .copied()
                .chain(PROVER_SHARD_L2)
                .collect();
            let mut id = PROVER_SHARD_L2.to_vec();
            id.extend_from_slice(addr);
            for (label, v) in [("pinned", version), ("latest", 0u64)] {
                match rpc(async {
                    if label == "pinned" {
                        client
                            .get_vertex_blob_at(shard_key.clone(), 0, id.clone(), v)
                            .await
                    } else {
                        client
                            .get_vertex_blob(shard_key.clone(), 0, id.clone(), v)
                            .await
                    }
                })
                .await
                {
                    Ok(Some(blob)) => {
                        println!("    blob  {label:<18} PRESENT  len={}", blob.len());
                        describe_vertex(&blob);
                    }
                    Ok(None) => println!("    blob  {label:<18} absent"),
                    Err(e) => println!("    blob  {label:<18} error: {e}"),
                }
            }
        }
    }
    Ok(())
}

/// Decode a served vertex blob far enough to say what class it is and whether
/// it carries a usable consensus key. Never prints key bytes — only lengths.
fn describe_vertex(blob: &[u8]) {
    let root = match quil_tries::deserialize_go_tree(blob) {
        Ok(Some(r)) => r,
        Ok(None) => {
            println!("      (empty tree)");
            return;
        }
        Err(e) => {
            println!("      (undecodable: {e})");
            return;
        }
    };
    let class = root
        .find_leaf_value(&[0xFFu8; 32])
        .and_then(|h| quil_execution::global_schema::class_for_type_hash(&h))
        .unwrap_or("<unknown class>");
    println!("      class={class}");
    if class != "prover:Prover" {
        return;
    }
    let field = |name: &str| {
        quil_execution::global_schema::field_key("prover:Prover", name)
            .and_then(|k| root.find_leaf_value(&k))
    };
    println!(
        "      public_key_len={} status={:?} seniority={:?}",
        field("PublicKey").map(|v| v.len()).unwrap_or(0),
        field("Status").map(|v| v.first().copied()),
        field("Seniority").map(|v| {
            let mut b = [0u8; 8];
            let n = v.len().min(8);
            b[8 - n..].copy_from_slice(&v[v.len() - n..]);
            u64::from_be_bytes(b)
        }),
    );
}

fn parse_versions(spec: &str) -> anyhow::Result<Vec<u64>> {
    let versions: Vec<u64> = spec
        .split(',')
        .map(|value| value.trim().parse())
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(!versions.is_empty(), "no versions given");
    Ok(versions)
}

fn report_read(result: anyhow::Result<Option<Vec<u8>>>) -> String {
    match result {
        Ok(Some(bytes)) => format!("PRESENT len={}", bytes.len()),
        Ok(None) => "absent".into(),
        Err(error) => format!("unavailable: {error}"),
    }
}

async fn rpc<T, E: std::error::Error + Send + Sync + 'static>(
    future: impl std::future::Future<Output = Result<T, E>>,
) -> anyhow::Result<T> {
    Ok(tokio::time::timeout(std::time::Duration::from_secs(30), future).await??)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_versions_are_strict_and_preserve_zero() {
        assert_eq!(parse_versions("0, 7,42").unwrap(), vec![0, 7, 42]);
        for input in ["", "7,typo", "7,", "-1"] {
            assert!(parse_versions(input).is_err(), "{input}");
        }
    }

    #[test]
    fn unavailable_reads_are_not_reported_as_absent() {
        assert_eq!(report_read(Ok(None)), "absent");
        assert_eq!(report_read(Ok(Some(vec![1]))), "PRESENT len=1");
        assert!(report_read(Err(anyhow::anyhow!("peer refused"))).starts_with("unavailable:"));
    }
}
