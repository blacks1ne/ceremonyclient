//! Read-only probe: does a `prover:Prover` vertex exist in ARCHIVE/canonical
//! state for a given prover address?
//!
//! Answers the open question left by the registry diagnostic
//! (`parent_vertex_state=absent`): the local node synthesizes a zero-key
//! `Unknown` parent for an allocation whose prover vertex it cannot find. This
//! probe asks one or more archives, over the same PQNoise/mTLS :8340 channel
//! the node's own sync uses, whether the canonical prover-shard tree
//! (`l2 = 0xff*32`) carries a leaf for that address in each of the four phases,
//! and whether the archive will serve the vertex blob.
//!
//! Reads only. It opens no local database and mutates nothing anywhere.
//!
//! Interpretation:
//!   - phase-0 leaf present + blob served  → the vertex IS canonical; the local
//!     node is missing it (a synchronization omission).
//!   - phase-0 leaf absent on every peer   → the vertex is absent canonically
//!     too; the allocations reference a prover record that no longer exists.
//!   - phase-0 leaf present AND phase-1 (removes) leaf present → the vertex is
//!     tombstoned canonically; local `adds ∧ ¬removes` correctly hides it.

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
#[command(about = "Probe archives for prover:Prover vertices in canonical state")]
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
        let mut client = match ArchiveClient::connect_mtls(peer, &falcon_signing_key).await {
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
            heads[phase] = client
                .get_forest_head(PROVER_SHARD_L2.to_vec(), phase as u32)
                .await
                .unwrap_or(None);
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

        if let Some(spec) = &args.versions {
            let shard_key: Vec<u8> = PROVER_SHARD_L1
                .iter()
                .copied()
                .chain(PROVER_SHARD_L2)
                .collect();
            for addr in &addresses {
                println!("  address {}", hex::encode(addr));
                let mut id = PROVER_SHARD_L2.to_vec();
                id.extend_from_slice(addr);
                for v in spec.split(',').filter_map(|v| v.trim().parse::<u64>().ok()) {
                    let leaf = client
                        .get_forest_value(PROVER_SHARD_L2.to_vec(), 0, v, addr.clone())
                        .await
                        .unwrap_or(None);
                    let blob = client
                        .get_vertex_blob(shard_key.clone(), 0, id.clone(), v)
                        .await
                        .unwrap_or(None);
                    println!(
                        "    v={:<8} leaf={:<7} blob={}",
                        v,
                        if leaf.is_some() { "PRESENT" } else { "absent" },
                        match blob {
                            Some(b) => format!("PRESENT len={}", b.len()),
                            None => "absent".to_string(),
                        }
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
                match client
                    .get_forest_value(
                        PROVER_SHARD_L2.to_vec(),
                        phase as u32,
                        version,
                        addr.clone(),
                    )
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
            // phase-0 version and, as a fallback, at latest (`0`).
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
                match client
                    .get_vertex_blob(shard_key.clone(), 0, id.clone(), v)
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
        .find_leaf_value(&vec![0xFFu8; 32])
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
